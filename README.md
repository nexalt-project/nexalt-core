Nexalt Core integration/staging tree
=====================================

[![Build Status](https://travis-ci.org/nexalt-project/nexalt.svg?branch=master)](https://travis-ci.org/nexalt-project/nexalt)

https://nexalt.org

What is Nexalt?
----------------

Nexalt is an experimental digital currency that enables instant payments to
anyone, anywhere in the world. Nexalt uses peer-to-peer technology to operate
with no central authority: managing transactions and issuing money are carried
out collectively by the network. Nexalt Core is the name of open source
software which enables the use of this currency.

For more information, as well as an immediately useable, binary version of
the Nexalt Core software, see [https://nexalt.org](https://nexalt.org).

License
-------

Nexalt Core is released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see https://opensource.org/licenses/MIT.

Development Process
-------------------

The `master` branch is regularly built and tested, but is not guaranteed to be
completely stable. [Tags](https://github.com/nexalt-project/nexalt/tags) are created
regularly to indicate new official, stable release versions of Nexalt Core.

The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md)
and useful hints for developers can be found in [doc/developer-notes.md](doc/developer-notes.md).

The developer [mailing list](https://groups.google.com/forum/#!forum/nexalt-dev)
should be used to discuss complicated or controversial changes before working
on a patch set.

Developer IRC can be found on Freenode at #nexalt-dev.

Testing
-------

Testing and code review is the bottleneck for development; we get more pull
requests than we can review and test on short notice. Please be patient and help out by testing
other people's pull requests, and remember this is a security-critical project where any mistake might cost people
lots of money.

### Automated Testing

Developers are strongly encouraged to write [unit tests](src/test/README.md) for new code, and to
submit new unit tests for old code. Unit tests can be compiled and run
(assuming they weren't disabled in configure) with: `make check`. Further details on running
and extending unit tests can be found in [/src/test/README.md](/src/test/README.md).

There are also [regression and integration tests](/test), written
in Python, that are run automatically on the build server.
These tests can be run (if the [test dependencies](/test) are installed) with: `test/functional/test_runner.py`

The Travis CI system makes sure that every pull request is built for Windows, Linux, and macOS, and that unit/sanity tests are run automatically.

### Manual Quality Assurance (QA) Testing

Changes should be tested by somebody other than the developer who wrote the
code. This is especially important for large or high-risk changes. It is useful
to add a test plan to the pull request description if testing the changes is
not straightforward.

Translations
------------

We only accept translation fixes that are submitted through [Bitcoin Core's Transifex page](https://www.transifex.com/projects/p/bitcoin/).
Translations are converted to Nexalt periodically.

Translations are periodically pulled from Transifex and merged into the git repository. See the
[translation process](doc/translation_process.md) for details on how this works.

**Important**: We do not accept translation changes as GitHub pull requests because the next
pull from Transifex would automatically overwrite them again.

How To Add sponsor Key?
------------
You can Add sponsor key by following methods:

1
---
GUI Method:
To add sponsor key you must need some amount in your wallet to pay some basic fee.
On main overview page their is a Button "Add sponsor Key" click on it a popup shows Add the key of your sponsor in it and click ok and than wait for some time that your key should be mined in BlockChain.

2
---
Console Method:
To add sponsor key you must need some amount in your wallet to pay some basic fee.
Than call "addmlckeyraw" and pass sponsor's key as argument and wait for some time that your key should be mined in BlockChain. 

Staking Setup
-------------
Follow these steps to enable staking reliably and quickly:

1. Configure `nexalt.conf` (daemon config)

   Create or edit `~/.nexalt/nexalt.conf` (Linux) and add:

```
server=1
rpcuser=<set-a-strong-user>
rpcpassword=<set-a-strong-password>
rpcallowip=127.0.0.1
rpcbind=127.0.0.1

# Networking (optional but recommended)
listen=1
maxconnections=64

# Staking
staking=1

# Fast validation gating during sync (optional)
# Keeps sync fast while still enforcing strict checks near tip.
fastmlc=1
# Adjust to a safe height buffer near current tip; set 0 to disable explicit height gating
mlcfastheight=0

# Optional indexes/utilities
txindex=1
```

2. Start the daemon

```
nexaltd -daemon
```

3. Verify staking status

```
nexalt-cli getstakinginfo
```

Expected fields should indicate staking is enabled and kernels are being searched when your wallet is unlocked and mature balance is available.

4. Wallet unlock for staking only (if wallet is encrypted)

```
nexalt-cli walletpassphrase "<your passphrase>" 99999999 true
```

The final `true` keeps the wallet unlocked for staking only.

5. Sponsor key (MLC) check (optional)

```
nexalt-cli getsponsorkey
```

If you previously added a sponsor key on this wallet, the node auto-restores it after resync. If needed, add it via GUI ("Add MLC Key") or:

```
nexalt-cli addmlckeyraw <SPONSOR_MLCK_TXID> true
```

Notes
-----
- `staking=1` enables proof-of-stake block creation on your node.
- `fastmlc`/`mlcfastheight` are optional runtime knobs for faster initial sync; strict validation resumes automatically near chain tip. You can set `fastmlc=0` to always enforce strict checks.
- Ensure your wallet has mature, spendable balance and system time is correct.