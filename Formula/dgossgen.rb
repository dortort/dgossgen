# typed: false
# frozen_string_literal: true

# This formula is auto-updated by the release workflow.
# To bootstrap a Homebrew tap:
#   1. Create repo: dortort/homebrew-tap
#   2. Copy this file to: homebrew-tap/Formula/dgossgen.rb
#   3. The release workflow will update it on each tagged release.
class Dgossgen < Formula
  desc "Generate dgoss-ready test suites from Dockerfiles"
  homepage "https://github.com/dortort/dgossgen"
  version "0.1.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/dortort/dgossgen/releases/download/v#{version}/dgossgen-aarch64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER"
    end
    if Hardware::CPU.intel?
      url "https://github.com/dortort/dgossgen/releases/download/v#{version}/dgossgen-x86_64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/dortort/dgossgen/releases/download/v#{version}/dgossgen-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "PLACEHOLDER"
    end
    if Hardware::CPU.intel?
      url "https://github.com/dortort/dgossgen/releases/download/v#{version}/dgossgen-x86_64-unknown-linux-musl.tar.gz"
      sha256 "PLACEHOLDER"
    end
  end

  def install
    bin.install "dgossgen"
  end

  test do
    system "#{bin}/dgossgen", "--version"
  end
end
