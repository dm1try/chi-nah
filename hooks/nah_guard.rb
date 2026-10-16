# frozen_string_literal: true

require "json"
require "open3"

# A before_tool_call guard that asks nah (https://github.com/manuelschipper/nah)
# about each shell and file call. nah blocks calls it can prove are
# catastrophic (secret exfiltration, rm -rf ~, git reset --hard, curl | sh …)
# and never approves one: its "delegate" leaves the call to chi's own
# allow/ask/deny rules.
#
# Each call runs `nah decide` once (~60 ms): one JSON object on stdin, the
# verdict on stdout, exit 1 block / 2 delegate / 3 no decision.
#
# Settings (config.yml, `bundles: chi-nah:`), all optional:
#   bin: nah              the nah executable (default: nah on PATH; an
#                         absolute path is safer for workers that chi web or
#                         the desktop helper start with a short PATH)
#   timeout: 2            seconds for one decision (write + run + read)
#   unavailable: notify   notify (default) | ask | deny: what happens when
#                         nah gives no decision (missing, timed out, exit 3,
#                         an answer that isn't a block or a delegate)
#   tools: [execute]      only these of execute, task_create, read, write,
#                         edit (default all five)
class NahGuard
  UNAVAILABLE = %w[notify ask deny].freeze
  TOOLS = %w[execute task_create read write edit].freeze
  DEFAULT_TIMEOUT = 2.0
  # Enough for any verdict; stderr past it is dropped.
  MAX_OUTPUT = 1 << 20
  CHUNK = 64 * 1024

  # The notify-once flag is per process: a worker builds its Engine (and
  # this hook) once, but chi may build more Engines in one process, and a
  # missing nah should not flood every session's view.
  @warned = false
  @warned_lock = Mutex.new

  class << self
    # @return [Boolean] true the first time in this process
    def first_warning!
      @warned_lock.synchronize do
        next false if @warned

        @warned = true
      end
    end

    # For tests.
    def reset_warning!
      @warned_lock.synchronize { @warned = false }
    end
  end

  def initialize(settings = {})
    settings = {} unless settings.is_a?(Hash)
    bin = settings["bin"].to_s.strip
    @bin = bin.empty? ? "nah" : bin
    @bin = File.expand_path(@bin) if @bin.start_with?("~")
    timeout = settings["timeout"].to_f
    @timeout = timeout.positive? ? timeout : DEFAULT_TIMEOUT
    mode = settings["unavailable"].to_s
    @unavailable = UNAVAILABLE.include?(mode) ? mode : "notify"
    tools = Array(settings["tools"]).map(&:to_s) & TOOLS
    @tools = tools.empty? ? TOOLS : tools
  end

  def call(event)
    return unless event.is_a?(Hash) && event[:type] == :before_tool_call

    call = event[:call] || {}
    return unless @tools.include?(call[:name].to_s)

    targets = event[:targets] || {}
    cwd = File.expand_path((targets[:cwd] || event.dig(:context, :cwd) || Dir.pwd).to_s)
    tool, input = lower(call, targets, cwd)
    return unless tool

    judge(event, decide(payload(tool, input, cwd)))
  rescue StandardError => e
    # A bug here must not let the call through silently: it goes where
    # every other missing decision goes.
    unavailable(event, "chi-nah failed: #{e.class}: #{e.message}")
  end

  private

  # chi's call → the Claude Code tool shape nah's adapters lower to.
  def lower(call, targets, cwd)
    case call[:name].to_s
    when "execute", "task_create"
      command = call[:content].to_s
      ["Bash", { command: command }] unless command.strip.empty?
    when "read"
      path = path_of(call[:content], targets, cwd)
      ["Read", { file_path: path }] if path
    when "write"
      path = path_of(call[:path], targets, cwd)
      ["Write", { file_path: path, content: call[:content].to_s }] if path
    when "edit"
      # An edit by line range has no old_text: nah takes an empty
      # old_string and judges the path and the new text.
      path = path_of(call[:path], targets, cwd)
      ["Edit", { file_path: path, old_string: call[:old_text].to_s, new_string: call[:new_text].to_s }] if path
    end
  end

  # The path chi resolved (absolute, normalized), else the model's own text
  # against the call's directory.
  def path_of(raw, targets, cwd)
    resolved = Array(targets[:paths]).first.to_s
    return resolved unless resolved.empty?

    raw = raw.to_s.strip
    raw.empty? ? nil : File.expand_path(raw, cwd)
  end

  def payload(tool, input, cwd)
    JSON.generate({ v: 1, tool: tool, input: utf8(input), cwd: utf8(cwd) })
  end

  # JSON wants UTF-8; a binary write's bytes are replaced rather than
  # failing the call.
  def utf8(value)
    case value
    when Hash then value.transform_values { |v| utf8(v) }
    when String
      text = value.encoding == Encoding::UTF_8 ? value : value.dup.force_encoding(Encoding::UTF_8)
      text.valid_encoding? ? text : text.scrub("?")
    else value
    end
  end

  # @return [Hash] {status:, body:} from nah, or {error:} when it gave none
  def decide(payload)
    deadline = now + @timeout
    Open3.popen3(@bin, "decide") do |stdin, stdout, stderr, waiter|
      writer = feed(stdin, payload)
      out = +""
      err = +""
      open = { stdout => out, stderr => err }
      until open.empty?
        left = deadline - now
        return give_up(waiter, writer) if left <= 0

        ready, = IO.select(open.keys, nil, nil, left)
        next unless ready

        ready.each do |io|
          chunk = io.read_nonblock(CHUNK, exception: false)
          next if chunk == :wait_readable

          if chunk.nil?
            open.delete(io)
          else
            buffer = open[io]
            buffer << chunk if buffer.bytesize < MAX_OUTPUT
          end
        end
      end
      return give_up(waiter, writer) unless waiter.join([deadline - now, 0].max)

      writer.join(0.1)
      status = waiter.value
      { status: status.exitstatus, body: parse(out), stderr: err.strip }
    end
  rescue SystemCallError => e
    { error: "nah could not run: #{e.message}" }
  end

  # The stdin write runs beside the reads, so a payload bigger than the
  # pipe buffer can't block before the deadline is watched.
  def feed(stdin, payload)
    Thread.new do
      Thread.current.report_on_exception = false
      begin
        stdin.write(payload)
      rescue IOError, SystemCallError
        nil # nah exited or was killed without reading it all
      ensure
        begin
          stdin.close
        rescue IOError
          nil
        end
      end
    end
  end

  # Past the deadline: kill nah (popen3's block reaps it) and report.
  def give_up(waiter, writer)
    begin
      Process.kill("KILL", waiter.pid)
    rescue SystemCallError
      nil
    end
    writer.join(0.5)
    { error: "nah gave no decision within #{format_seconds(@timeout)}" }
  end

  def parse(text)
    body = JSON.parse(text, symbolize_names: true)
    body.is_a?(Hash) ? body : nil
  rescue JSON::ParserError
    nil
  end

  # Only two answers count: exit 1 with a block and its reason, exit 2
  # with a delegate. Anything else is no decision.
  def judge(event, decision)
    return unavailable(event, decision[:error]) if decision[:error]

    case decision
    in { status: 1, body: { verdict: "block", reason: String => reason } } unless reason.strip.empty?
      names = guard_names(decision[:body])
      event[:guardrail].deny!(deny_reason(reason, names), rule: names.empty? ? nil : names.join(", "), source: "nah")
    in { status: 2, body: { verdict: "delegate" } }
      nil
    else
      unavailable(event, no_decision(decision))
    end
  end

  # nah gives one line per guard that blocked; the deny is one line.
  def one_line(reason)
    reason.lines.map(&:strip).reject(&:empty?).join("; ")
  end

  # nah's reason, then how the user pauses the guards: a model told only
  # to "ask the user" tends to offer a retry that can never pass. A
  # self-protection block names no guard (its reason already says nah nap).
  def deny_reason(reason, names)
    text = one_line(reason)
    return text if names.empty?

    "#{text}; the user can pause #{names.size == 1 ? "it" : "them"} with " \
      "`nah nap #{names.join(" ")}` in their own terminal"
  end

  # ["secrets-env", "secrets-exfil"]; [] for a block no named guard made
  # (nah's self-protection), so the deny reads "(nah)".
  def guard_names(body)
    Array(body[:policy_attributions]).filter_map { |a| a[:name].to_s if a.is_a?(Hash) && a[:name] }
                                     .reject(&:empty?).uniq
  end

  def no_decision(decision)
    status = decision[:status]
    detail = decision[:stderr].to_s.lines.last.to_s.strip
    what = case status
           when 1, 2 then "nah exited #{status} with an answer chi-nah doesn't understand"
           else "nah exited #{status.inspect}"
           end
    detail.empty? ? what : "#{what}: #{detail}"
  end

  def unavailable(event, error)
    case @unavailable
    when "deny"
      event[:guardrail].deny!("#{error}; chi-nah is set to deny when nah gives no decision",
                              rule: "nah-unavailable", source: "nah")
    when "ask"
      # once / session only: a standing approval would hide later failures.
      event[:guardrail].ask!("#{error}; nah gave no decision", scopes: %w[once session],
                                                               rule: "nah-unavailable", source: "nah")
    else
      notify_once(event, error)
    end
  end

  def notify_once(event, error)
    if self.class.first_warning!
      event[:notify]&.call("nah gave no decision (#{error}); chi's own rules decide. " \
                           "Further misses are logged only.", level: :warn)
    else
      log(error)
    end
  end

  # chi's structured log when this runs inside chi; nothing otherwise.
  def log(error)
    return unless defined?(::Samagotchi::Log) && ::Samagotchi::Log.respond_to?(:warn)

    ::Samagotchi::Log.warn("hooks", "nah_unavailable", msg: error)
  rescue StandardError
    nil
  end

  def now = Process.clock_gettime(Process::CLOCK_MONOTONIC)

  def format_seconds(value)
    value == value.to_i ? "#{value.to_i}s" : "#{value}s"
  end
end
