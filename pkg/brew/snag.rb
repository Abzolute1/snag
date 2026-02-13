class Snag < Formula
  desc "P2P file sharing from your terminal"
  homepage "https://github.com/Abzolute1/snag"
  url "https://github.com/Abzolute1/snag/archive/v0.1.0.tar.gz"
  sha256 "PLACEHOLDER"
  license any_of: ["MIT", "Apache-2.0"]
  head "https://github.com/Abzolute1/snag.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
    man1.install "man/snag.1"

    # Generate and install shell completions
    ENV["GENERATE_COMPLETIONS"] = "1"
    system "cargo", "build", "--release"
    bash_completion.install Dir["target/release/build/snag-*/out/completions/snag.bash"].first => "snag"
    zsh_completion.install Dir["target/release/build/snag-*/out/completions/_snag"].first
    fish_completion.install Dir["target/release/build/snag-*/out/completions/snag.fish"].first
  end

  test do
    assert_match "P2P file sharing", shell_output("#{bin}/snag --help")
  end
end
