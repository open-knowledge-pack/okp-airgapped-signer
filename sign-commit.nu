# Sign the last commit with a key that lives on another device.
#
#   use sign-commit.nu
#   sign-commit | qrencode --type ANSIUTF8  # HEAD's bytes, for the signer
#   $sig | sign-commit apply                # put the block into HEAD
#
# The same two-step shape as `seal --external-signer` in nu-multiproof: the
# first step returns the bytes, because the round trip through a phone can
# take longer than a command should wait; the second step checks the block
# over the same bytes before it writes anything.

# The commit object exactly as git hashes it, final LF included.
# Why `complete`: a plain capture of external output drops the trailing LF,
# and that LF is part of the signed bytes.
def commit-bytes [repo: path rev: string]: nothing -> string {
    let out = ^git -C $repo cat-file commit $rev | complete

    if $out.exit_code != 0 {
        error make {msg: $"git cat-file commit ($rev) failed: ($out.stderr | str trim)"}
    }
    $out.stdout
}

# Catches both `gpgsig` and `gpgsig-sha256`.
def refuse-signed [bytes: string]: nothing -> nothing {
    if ($bytes | lines | take until { $in == "" } | any { $in starts-with "gpgsig" }) {
        error make {msg: "HEAD is already signed; git signs the object without its signature header" help: "sign a commit with no signature"}
    }
}

# The public key line that user.signingKey names, inline or by path.
def configured-key [repo: path]: nothing -> string {
    let hint = "set user.signingKey to the public key of the signer: git config user.signingKey <key>.pub, or pass --pubkey <key>.pub"
    let out = ^git -C $repo config user.signingKey | complete

    if $out.exit_code != 0 {
        error make {msg: $hint}
    }
    let key = $out.stdout | str trim

    if ($key starts-with "key::") {
        return ($key | str substring 5..)
    }
    let key_path = $repo | path join $key | path expand

    if not ($key_path | path exists) {
        error make {msg: $hint}
    }
    open --raw $key_path | str trim
}

# The bytes of HEAD to sign: raw mode, namespace `git`, final LF included.
#
# js-okp-signer: untick "Sign as a file", namespace git; compare the digest
# on the page with `sign-commit | hash sha256`.
# nu-okp-signer: `sign-commit | nu-okp-signer sign $key --raw --namespace git`.
export def main [
    --repo: path = "." # the repository whose HEAD is signed
]: nothing -> string {
    let bytes = commit-bytes $repo HEAD

    refuse-signed $bytes
    $bytes
}

# Put an SSHSIG block into HEAD's signature header and move the branch to it.
# The block comes in the pipeline, BEGIN and END lines included.
# Returns the id of the signed commit.
export def apply [
    --repo: path = "." # the repository whose HEAD is signed
    --pubkey: path # the public half of the signer's key (default: user.signingKey)
]: string -> string {
    let block = $in | str trim
    let old = ^git -C $repo rev-parse HEAD | str trim
    let bytes = commit-bytes $repo $old

    refuse-signed $bytes

    # Why check with ssh-keygen before writing: a block over other bytes, or by
    # another key, would give a commit that only fails later, in
    # `git verify-commit`. The key is the public half only, as in
    # `seal --external-signer`.
    # Why --pubkey: to sign with the key nu-multiproof registered without
    # changing user.signingKey for the repo.
    let pubkey = if $pubkey != null {
        open --raw $pubkey | str trim
    } else {
        configured-key $repo
    }
    let tmp = mktemp --directory

    $"signer ($pubkey)\n" | save $"($tmp)/allowed"
    $block + "\n" | save $"($tmp)/sig"
    let check = $bytes | ^ssh-keygen -Y verify -f $"($tmp)/allowed" -I signer -n git -s $"($tmp)/sig" | complete

    rm --recursive $tmp
    if $check.exit_code != 0 {
        error make {msg: $"not a signature by the signer's key over HEAD under namespace git: ($check.stdout + $check.stderr | str trim)"}
    }

    # git's own layout: the header goes last among the headers, every line of
    # the block after the first is indented by one space, and a SHA-256 repo
    # names it `gpgsig-sha256` — under plain `gpgsig` there, verify-commit
    # reports the commit as unsigned.
    let name = match (^git -C $repo rev-parse --show-object-format | str trim) {
        "sha256" => "gpgsig-sha256"
        _ => "gpgsig"
    }
    let header = $name + " " + ($block | lines | str join "\n ")
    let signed = $bytes | str replace "\n\n" $"\n($header)\n\n"

    let new = $signed | ^git -C $repo hash-object -t commit -w --stdin | str trim

    # Why the old value: if HEAD moved since the read above, refuse rather
    # than drop the commit that moved it.
    ^git -C $repo update-ref -m "sign-commit: external signer" HEAD $new $old
    $new
}
