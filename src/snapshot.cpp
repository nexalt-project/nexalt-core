// Copyright (c) 2025 Nexalt Core contributors
// MIT License

#include <snapshot.h>
#include <logging.h>
#include <util/system.h>
#include <fs.h>
#include <mlcdb.h>

static bool ReadFileToString(const fs::path& p, std::string& out)
{
    FILE* f = fsbridge::fopen(p, "rb");
    if (!f) return false;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return false; }
    fseek(f, 0, SEEK_SET);
    out.resize((size_t)sz);
    size_t r = fread(&out[0], 1, (size_t)sz, f);
    fclose(f);
    return r == (size_t)sz;
}

bool Snapshot::LoadManifest(const std::string& snapshotPath, SnapshotManifest& out)
{
    fs::path manifest = fs::path(snapshotPath) / "manifest.json";
    std::string data;
    if (!ReadFileToString(manifest, data)) return false;
    // Extremely simple parse (key:value per line). Replace with proper JSON if needed.
    out = SnapshotManifest();
    size_t pos = 0;
    auto findkv = [&](const char* key)->std::string{
        size_t k = data.find(key);
        if (k == std::string::npos) return std::string();
        size_t v = data.find(":", k);
        if (v == std::string::npos) return std::string();
        size_t eol = data.find_first_of("\r\n", v+1);
        std::string val = data.substr(v+1, eol == std::string::npos ? std::string::npos : eol-(v+1));
        // trim
        size_t a = val.find_first_not_of(" \t\"{}");
        size_t b = val.find_last_not_of(" \t\"{},");
        if (a==std::string::npos || b==std::string::npos) return std::string();
        return val.substr(a, b-a+1);
    };
    std::string h = findkv("height");
    if (!h.empty()) out.height = atoi(h.c_str());
    out.blockHashHex    = findkv("blockhash");
    out.mlcHashHex      = findkv("mlchash");
    out.chainstateHashHex = findkv("chainstatehash");
    out.signatureHex    = findkv("signature");
    return out.height > 0 && !out.blockHashHex.empty();
}

bool Snapshot::VerifyManifest(const SnapshotManifest& m)
{
    // TODO: signature verification. For now, basic sanity.
    if (m.height <= 0) return false;
    if (m.blockHashHex.size() != 64) return false;
    return true;
}

bool Snapshot::MaybeInstallMlcSnapshot(const std::string& snapshotPath)
{
    fs::path mlcDump = fs::path(snapshotPath) / "mlc.txt"; // simple key\tvalue per line
    if (!fs::exists(mlcDump)) return true; // nothing to do

    // If DB already has many entries, skip bulk load to avoid duplicate work
    // (We keep it simple: try to insert; duplicates will overwrite harmlessly.)
    LogPrintf("[SNAPSHOT] Installing MLC snapshot from %s\n", mlcDump.string());
    FILE* f = fsbridge::fopen(mlcDump, "rb");
    if (!f) return false;
    char* line = nullptr; size_t cap = 0; ssize_t n;
    while ((n = getline(&line, &cap, f)) > 0) {
        std::string s(line, (size_t)n);
        size_t tab = s.find('\t');
        if (tab == std::string::npos) continue;
        std::string key = s.substr(0, tab);
        std::string val = s.substr(tab+1);
        // strip newline
        while (!val.empty() && (val.back()=='\n' || val.back()=='\r')) val.pop_back();
        if (!key.empty() && !val.empty()) {
            MlcDb::Instance().PutMlc(key, val);
        }
    }
    if (line) free(line);
    fclose(f);
    LogPrintf("[SNAPSHOT] MLC snapshot installed\n");
    return true;
}

void Snapshot::StartBackgroundMlcVerifier()
{
    // Placeholder: in future, walk historical blocks and verify/patch MLC index.
    LogPrintf("[SNAPSHOT] Background MLC verifier (stub) started\n");
}


