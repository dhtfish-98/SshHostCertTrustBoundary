# Third-party rights

The source archive contains this project's own Go source, tests, documents, `go.mod`, and `go.sum`. It does not vendor third-party source or include the locally built executable.

- `golang.org/x/crypto` is fixed to commit `8f0f1112abdbc13b6e53068b813cc327e40f2f9f`, module `v0.57.1-0.20261004121123-8f0f1112abdb`, under [BSD-3-Clause](https://github.com/golang/crypto/blob/8f0f1112abdbc13b6e53068b813cc327e40f2f9f/LICENSE). Copyright and license remain with the Go authors and contributors.
- The resolved Go module graph also lists `golang.org/x/net@v0.58.0`, `golang.org/x/sys@v0.48.0`, `golang.org/x/term@v0.46.0`, and `golang.org/x/text@v0.42.0`. They retain their own notices and licenses. Go may retrieve these modules into the local `Build` cache during validation; none is vendored in the source archive.

The local installed binary links those dependencies for integration testing. It remains inside `Build` and is not proposed for public release. If a binary is ever distributed, its bundled third-party license notices must be reviewed separately.
