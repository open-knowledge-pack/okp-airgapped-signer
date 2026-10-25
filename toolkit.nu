# Commands of the signer repo: nu toolkit.nu <command>

# VERSION in js-okp-signer/sw.js is '<date>.<hash>': the hash is the first 12
# hex digits of sha256 over the files in FILES, joined in their order, and the
# date is when that hash last changed. A new hash is what makes an installed
# app fetch the new files.
# Why only the hash is checked: the date is for people, and a wrong date
# breaks nothing.

const SIGNER = path self ./js-okp-signer
const VERSION_LINE = "(?m)^const VERSION = '(?<version>[^']*)';$"

export def main [] { }

# The bytes of a file in js-okp-signer/: on disk, or in a commit
def read-file [file: string rev?: string]: nothing -> binary {
    if $rev == null {
        open --raw ($SIGNER | path join $file) | into binary
    } else {
        ^git -C $SIGNER show $"($rev):./($file)" | into binary
    }
}

# The VERSION that sw.js holds, and the VERSION that its files call for
def versions [rev?: string]: nothing -> record<held: string, hash: string> {
    let sw = read-file sw.js $rev | decode utf-8

    # FILES without './', which is index.html again
    let files = $sw
        | parse --regex "(?m)^const FILES = (?<list>\\[.*\\]);$"
        | get list.0
        | str replace --all "'" '"'
        | from json
        | where $it != './'
        | uniq

    let hash = $files
        | each { read-file $in $rev }
        | bytes collect
        | hash sha256
        | str substring 0..11

    {
        held: ($sw | parse --regex $VERSION_LINE | get version.0)
        hash: $hash
    }
}

# Fail unless VERSION in sw.js carries the hash of the files it caches
@example "check the files on disk" { nu toolkit.nu check }
@example "check the commit that an export sends" { nu toolkit.nu check --rev master }
export def 'main check' [
    --rev: string # check this commit instead of the files on disk
]: nothing -> string {
    let v = versions $rev

    if $v.held !~ $'^\d{4}-\d{2}-\d{2}\.($v.hash)$' {
        error make --unspanned {
            msg: $"sw.js VERSION is '($v.held)', the cached files hash to ($v.hash)"
            help: 'run `nu toolkit.nu sw-version`, then commit sw.js'
        }
    }

    $v.held
}

# Write the VERSION that the files on disk call for into sw.js
# Why the date stays while the hash is the same: a second run on a later day
# then changes nothing.
export def 'main sw-version' []: nothing -> string {
    let v = versions

    if ($v.held | str ends-with $'.($v.hash)') { return $v.held }

    let date = date now | format date '%Y-%m-%d'
    let next = $'($date).($v.hash)'
    let sw = $SIGNER | path join sw.js

    open --raw $sw
    | decode utf-8
    | str replace --regex $VERSION_LINE $"const VERSION = '($next)';"
    | save --force $sw

    $next
}
