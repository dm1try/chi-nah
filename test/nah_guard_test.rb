# frozen_string_literal: true

# Standalone tests for hooks/nah_guard.rb: no chi needed. A fake `nah`
# (test/fake/nah) answers per FAKE_NAH_MODE.
#
#   ruby -Itest test/nah_guard_test.rb
require "minitest/autorun"
require "json"
require "tmpdir"
require "yaml"
require "digest"
require "fileutils"
require_relative "../hooks/nah_guard"

class NahGuardTest < Minitest::Test
  FAKE_DIR = File.expand_path("fake", __dir__)
  FAKE = File.join(FAKE_DIR, "nah")

  # Records the votes a chi Verdict would get.
  class StubGuardrail
    attr_reader :votes

    def initialize = @votes = []
    def deny!(reason, **opts) = @votes << [:deny, reason, opts]
    def ask!(reason, **opts) = @votes << [:ask, reason, opts]
  end

  def setup
    NahGuard.reset_warning!
    @dir = Dir.mktmpdir("chi-nah-test")
    @log = File.join(@dir, "stdin.log")
    ENV["FAKE_NAH_LOG"] = @log
    ENV["FAKE_NAH_MODE"] = "delegate"
  end

  def teardown
    FileUtils.rm_rf(@dir)
    ENV.delete("FAKE_NAH_LOG")
    ENV.delete("FAKE_NAH_MODE")
  end

  # --- helpers ---------------------------------------------------------

  def event(call, targets: {}, cwd: @dir)
    notices = []
    {
      type: :before_tool_call, iteration: 1, call: call, params: "",
      guardrail: StubGuardrail.new, context: { cwd: cwd },
      targets: { cwd: cwd }.merge(targets),
      notify: ->(text, level: :info, **) { notices << [text, level] },
      notices: notices
    }
  end

  def guard(settings = {})
    NahGuard.new({ "bin" => FAKE }.merge(settings))
  end

  def run_mode(mode, call = execute("cat .env"), settings: {}, **kw)
    ENV["FAKE_NAH_MODE"] = mode
    ev = event(call, **kw)
    guard(settings).call(ev)
    ev
  end

  def execute(command) = { name: "execute", content: command }

  def sent
    File.readlines(@log).map { |line| JSON.parse(line) }
  end

  def votes(ev) = ev[:guardrail].votes

  def timed
    t = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    yield
    Process.clock_gettime(Process::CLOCK_MONOTONIC) - t
  end

  # --- verdicts --------------------------------------------------------

  def test_block_denies_with_the_guard_names_and_no_advice
    ev = run_mode("block")
    assert_equal 1, votes(ev).size
    kind, reason, opts = votes(ev).first
    assert_equal :deny, kind
    assert_equal "secrets-env blocked reading a credential file; secrets-exfil blocked sending it; " \
                 "the user can pause them with `nah nap secrets-env secrets-exfil` in their own terminal", reason
    assert_equal({ rule: "secrets-env, secrets-exfil", source: "nah" }, opts)
    refute opts.key?(:advice), "advice: would replace chi's do-not-retry tail"
  end

  def test_one_guard_gets_a_singular_nap_hint
    ev = run_mode("block_one")
    assert_equal "git-hard-reset blocked git reset --hard; " \
                 "the user can pause it with `nah nap git-hard-reset` in their own terminal", votes(ev).first[1]
    assert_equal "git-hard-reset", votes(ev).first[2][:rule]
  end

  def test_block_without_a_named_guard_has_no_rule_and_no_nap_hint
    ev = run_mode("block_self")
    kind, reason, opts = votes(ev).first
    assert_equal :deny, kind
    assert_equal "nah self-protection blocked a change to nah", reason
    assert_equal({ rule: nil, source: "nah" }, opts)
  end

  def test_delegate_votes_nothing_and_says_nothing
    ev = run_mode("delegate")
    assert_empty votes(ev)
    assert_empty ev[:notices]
  end

  # --- every bad answer lands in `unavailable` -------------------------

  BAD_MODES = %w[exit3 exit4 garbage block_noreason block_emptyreason block_exit2 delegate_exit1 array].freeze

  BAD_MODES.each do |mode|
    define_method("test_#{mode}_is_unavailable_notify") do
      ev = run_mode(mode)
      assert_empty votes(ev), "#{mode} must not vote under notify"
      assert_equal 1, ev[:notices].size, "#{mode} must notify"
      assert_equal :warn, ev[:notices].first[1]
    end

    define_method("test_#{mode}_is_unavailable_deny") do
      ev = run_mode(mode, settings: { "unavailable" => "deny" })
      assert_equal [:deny], votes(ev).map(&:first), "#{mode} must deny under unavailable: deny"
      assert_equal "nah-unavailable", votes(ev).first[2][:rule]
    end
  end

  def test_exit3_reason_names_nahs_stderr
    ev = run_mode("exit3", settings: { "unavailable" => "deny" })
    assert_match(/nah exited 3: nah: invalid input/, votes(ev).first[1])
  end

  def test_ask_offers_only_once_and_session
    ev = run_mode("exit3", settings: { "unavailable" => "ask" })
    kind, _reason, opts = votes(ev).first
    assert_equal :ask, kind
    assert_equal %w[once session], opts[:scopes]
    assert_equal "nah-unavailable", opts[:rule]
  end

  def test_missing_binary_is_unavailable
    ev = event(execute("ls"))
    NahGuard.new("bin" => File.join(@dir, "no-such-nah"), "unavailable" => "deny").call(ev)
    assert_equal :deny, votes(ev).first[0]
    assert_match(/nah could not run/, votes(ev).first[1])
  end

  def test_unknown_unavailable_setting_falls_back_to_notify
    ev = run_mode("exit3", settings: { "unavailable" => "explode" })
    assert_empty votes(ev)
    assert_equal 1, ev[:notices].size
  end

  def test_notify_warns_once_per_process
    first = run_mode("exit3")
    second = run_mode("exit3")
    assert_equal 1, first[:notices].size
    assert_empty second[:notices]
    assert_empty votes(second)
  end

  def test_an_internal_error_is_unavailable_not_a_silent_pass
    ev = event(execute("ls"))
    ev[:context] = "not a hash"
    ev[:targets] = { cwd: nil } # forces the context lookup
    NahGuard.new("bin" => FAKE, "unavailable" => "deny").call(ev)
    assert_equal :deny, votes(ev).first[0]
    assert_match(/chi-nah failed/, votes(ev).first[1])
  end

  # --- the deadline ----------------------------------------------------

  def test_a_hang_is_killed_at_the_deadline
    ev = nil
    took = timed { ev = run_mode("hang", settings: { "timeout" => 0.5, "unavailable" => "deny" }) }
    assert_operator took, :<, 1.5
    assert_match(/no decision within 0.5s/, votes(ev).first[1])
  end

  def test_a_big_write_nah_never_reads_still_meets_the_deadline
    call = { name: "write", path: "big.txt", content: "x" * 200_000 }
    ev = nil
    took = timed { ev = run_mode("noread", call, settings: { "timeout" => 0.5, "unavailable" => "deny" }) }
    assert_operator took, :<, 1.5
    assert_equal :deny, votes(ev).first[0]
    assert_match(/no decision within/, votes(ev).first[1])
  end

  def test_an_answer_before_reading_stdin_still_counts
    call = { name: "write", path: "big.txt", content: "x" * 200_000 }
    ev = run_mode("noread_delegate", call)
    assert_empty votes(ev)
    assert_empty ev[:notices]
  end

  def test_a_stderr_flood_does_not_deadlock
    ev = run_mode("stderr_flood")
    assert_empty votes(ev)
    assert_empty ev[:notices]
  end

  def test_the_hung_process_is_gone_after_the_deadline
    ENV["FAKE_NAH_MODE"] = "hang"
    before = fake_pids
    guard("timeout" => 0.3).call(event(execute("ls")))
    sleep 0.1
    assert_empty fake_pids - before
  end

  # --- what nah is sent -----------------------------------------------

  def test_execute_and_task_create_go_as_bash_with_the_call_cwd
    run_mode("delegate", execute("git status"), targets: { cwd: "/repo/sub" })
    run_mode("delegate", { name: "task_create", content: "make test" })
    first, second = sent
    assert_equal({ "v" => 1, "tool" => "Bash", "input" => { "command" => "git status" }, "cwd" => "/repo/sub" }, first)
    assert_equal "Bash", second["tool"]
    assert_equal "make test", second["input"]["command"]
    assert_equal File.realpath(@dir), File.realpath(second["cwd"])
  end

  def test_read_write_edit_send_the_resolved_path
    abs = File.join(@dir, "lib", "a.rb")
    run_mode("delegate", { name: "read", content: "lib/a.rb" }, targets: { paths: [abs] })
    run_mode("delegate", { name: "write", path: "lib/a.rb", content: "puts 1\n" }, targets: { paths: [abs] })
    run_mode("delegate", { name: "edit", path: "lib/a.rb", old_text: "1", new_text: "2" }, targets: { paths: [abs] })
    read, write, edit = sent
    assert_equal({ "tool" => "Read", "input" => { "file_path" => abs } }, read.slice("tool", "input"))
    assert_equal({ "file_path" => abs, "content" => "puts 1\n" }, write["input"])
    assert_equal({ "file_path" => abs, "old_string" => "1", "new_string" => "2" }, edit["input"])
    assert_equal "Edit", edit["tool"]
  end

  def test_a_relative_path_without_targets_is_resolved_against_the_cwd
    run_mode("delegate", { name: "read", content: "../x/.env" }, targets: { cwd: "/repo/sub" })
    assert_equal "/repo/x/.env", sent.first["input"]["file_path"]
  end

  def test_a_line_range_edit_sends_an_empty_old_string
    run_mode("delegate", { name: "edit", path: "a.rb", old_text: nil, new_text: "x", start_line: 3 })
    assert_equal "", sent.first["input"]["old_string"]
  end

  def test_binary_write_content_is_sent_as_valid_utf8
    run_mode("delegate", { name: "write", path: "b.bin", content: "\xFF\xFEok".b })
    assert_equal "??ok", sent.first["input"]["content"]
  end

  def test_other_tools_and_empty_calls_start_no_process
    run_mode("block", { name: "memory_write", path: "notes", content: "x" })
    run_mode("block", { name: "web_fetch", content: "https://example.com" })
    run_mode("block", execute("   "))
    run_mode("block", { name: "read", content: "" })
    refute File.exist?(@log)
  end

  def test_tools_setting_limits_the_tools
    ev = run_mode("block", { name: "read", content: ".env" }, settings: { "tools" => ["execute"] })
    assert_empty votes(ev)
    ev = run_mode("block", execute("cat .env"), settings: { "tools" => ["execute"] })
    assert_equal :deny, votes(ev).first[0]
  end

  def test_other_events_are_ignored
    ENV["FAKE_NAH_MODE"] = "block"
    ev = event(execute("ls")).merge(type: :after_tool_call)
    guard.call(ev)
    assert_empty votes(ev)
    refute File.exist?(@log)
  end

  # --- settings ---------------------------------------------------------

  def test_default_bin_is_nah_on_path
    old = ENV["PATH"]
    ENV["PATH"] = "#{FAKE_DIR}#{File::PATH_SEPARATOR}#{old}"
    ENV["FAKE_NAH_MODE"] = "block"
    ev = event(execute("cat .env"))
    NahGuard.new.call(ev)
    assert_equal :deny, votes(ev).first[0]
  ensure
    ENV["PATH"] = old
  end

  def test_bad_timeout_falls_back_to_the_default
    assert_equal 2.0, NahGuard.new("timeout" => "soon").instance_variable_get(:@timeout)
    assert_equal 2.0, NahGuard.new("timeout" => -1).instance_variable_get(:@timeout)
    assert_equal 0.25, NahGuard.new("timeout" => 0.25).instance_variable_get(:@timeout)
  end

  # --- the manifest -----------------------------------------------------

  def test_manifest_checksums_match_the_files
    root = File.expand_path("..", __dir__)
    manifest = YAML.load_file(File.join(root, "manifest.yml"))
    entries = manifest.fetch("hooks", {}).transform_keys { |k| File.join("hooks", k) }
                      .merge(manifest.fetch("files", {}))
    refute_empty entries
    entries.each do |file, entry|
      sha = entry.is_a?(Hash) ? entry["sha256"] : entry
      actual = "sha256:#{Digest::SHA256.file(File.join(root, file)).hexdigest}"
      assert_equal actual, sha, "#{file}: run script/sha"
    end
  end

  def test_no_markdown_but_the_memories_at_the_root
    # chi installs every top-level *.md as a memory.
    root = File.expand_path("..", __dir__)
    manifest = YAML.load_file(File.join(root, "manifest.yml"))
    listed = manifest.fetch("files", {}).keys
    assert_equal listed.sort, Dir.glob("*.md", base: root).sort
  end

  private

  def fake_pids
    `pgrep -f #{FAKE}`.split.map(&:to_i)
  end
end
