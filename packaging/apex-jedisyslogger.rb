# Homebrew formula — macOS (Apple silicon and Intel) and Linuxbrew.
#
#   brew install --formula ./packaging/apex-jedisyslogger.rb
#
# Nothing is built: `node` runs the sources as they are. The formula exists so
# `jedi` lands on PATH and upgrades come through brew like anything else.
class ApexJedisyslogger < Formula
  desc "SIEM log-ingestion simulator with a terminal dashboard and 72 attack scenarios"
  homepage "https://github.com/alfredonacino/APEX-Jedi-Syslogger"
  url "https://github.com/alfredonacino/APEX-Jedi-Syslogger/releases/download/v1.2.4/apex-jedisyslogger-1.2.4.tar.gz"
  version "1.2.4"
  sha256 "REPLACE_WITH_THE_SHA256SUMS_ENTRY"
  # No licence declared upstream yet; add `license "..."` once there is one.

  depends_on "node" => :run

  def install
    libexec.install Dir["*"]
    (bin/"jedi").write <<~SH
      #!/bin/sh
      exec "#{Formula["node"].opt_bin}/node" "#{libexec}/jedi-cli.js" "$@"
    SH
    chmod 0755, bin/"jedi"
    doc.install Dir[libexec/"*.md"]
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/jedi --version")
    assert_match "72 attack scenarios", shell_output("#{bin}/jedi list scenarios 2>&1")
    # The update check must reach the channel and verify its signature.
    assert_match(/Up to date|Update available|not be published/, shell_output("#{bin}/jedi update 2>&1", 1))
  end
end
