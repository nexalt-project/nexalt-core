// Copyright (c) 2025 Nexalt Core contributors
// MIT License

#ifndef NEXALT_SNAPSHOT_H
#define NEXALT_SNAPSHOT_H

#include <string>
#include <stdint.h>

struct SnapshotManifest {
    int height = 0;
    std::string blockHashHex;     // block hash at snapshot height
    std::string mlcHashHex;       // optional: hash of MLC DB payload
    std::string chainstateHashHex; // optional: hash of chainstate payload (future)
    std::string signatureHex;     // optional: signature over manifest
};

namespace Snapshot {

// Tries to load manifest from -snapshot path
bool LoadManifest(const std::string& snapshotPath, SnapshotManifest& out);

// Verify manifest (signature/key TBD). Currently basic sanity checks only
bool VerifyManifest(const SnapshotManifest& m);

// Install only the MLC DB portion from snapshot if present and not already populated.
// Returns true if installed or already present, false on hard failure.
bool MaybeInstallMlcSnapshot(const std::string& snapshotPath);

// Starts a lightweight background verifier to backfill/verify historical MLC entries up to manifest height
void StartBackgroundMlcVerifier();

}

#endif // NEXALT_SNAPSHOT_H


