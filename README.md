# HotStuff with Proof of Availability
This code implements lazy-dolphin but has the leader send out 2 fragments initially and prune down to 1 upon receiving sufficient responses. It also use a (2F+1, 2N) encoding scheme instead of (F+1, N)
[![build status](https://img.shields.io/github/workflow/status/asonnino/hotstuff/Build/lazy-dolphin?style=flat-square&logo=github)](https://github.com/asonnino/hotstuff/actions)
[![rustc](https://img.shields.io/badge/rustc-1.51+-blue?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![license](https://img.shields.io/badge/license-Apache-blue.svg?style=flat-square)](LICENSE)

The code in this branch is a prototype of HotStuff using a Proof of Availability (PoA) scheme as mempool and synchronizer. It supplements the paper [Using Proof of Availability for a Composable Blockchain Architecture ]() and there are no plans to maintain this branch. All data points used to produce the graphs of the paper are available in the folder [hotstuff/benchmark/data](benchmark/data/).

## License
This software is licensed as [Apache 2.0](LICENSE).
