// Copyright (c) 2025 Nexalt Core contributors
// Distributed under the MIT software license.

#ifndef NEXALT_MLCDB_H
#define NEXALT_MLCDB_H

#include <string>
#include <mutex>
#include <unordered_map>
#include <list>

namespace leveldb {
class DB;
class Cache;
class FilterPolicy;
}

// Lightweight thread-safe LRU cache for string->string lookups.
class StringLruCache {
public:
    explicit StringLruCache(size_t capacityEntries);

    bool get(const std::string& key, std::string& value);
    void put(const std::string& key, const std::string& value);
    void clear();

private:
    using ListIt = std::list<std::pair<std::string, std::string>>::iterator;
    size_t m_capacity;
    std::list<std::pair<std::string, std::string>> m_list;
    std::unordered_map<std::string, ListIt> m_map;
};

// Centralized persistent LevelDB access for MLC and myKey stores.
// This wrapper preserves existing read/write semantics while removing
// repeated open/close overhead and adding in-memory caching for hot reads.
class MlcDb {
public:
    // Returns singleton instance
    static MlcDb& Instance();

    // Ensure DBs are opened (lazy-open by default)
    void EnsureOpen();

    // MLC mapping: key -> sponsor
    bool GetMlc(const std::string& key, std::string& value);
    bool PutMlc(const std::string& key, const std::string& value);

    // myKey mapping: wallet-scoped string keys
    bool GetMyKey(const std::string& key, std::string& value);
    bool PutMyKey(const std::string& key, const std::string& value);

    // Testing/maintenance
    void ClearCaches();

private:
    MlcDb();
    ~MlcDb();
    MlcDb(const MlcDb&) = delete;
    MlcDb& operator=(const MlcDb&) = delete;

    void OpenLocked();

    // Guards
    std::mutex m_openMutex;
    std::mutex m_mlcMutex;
    std::mutex m_myMutex;

    // DB handles
    leveldb::DB* m_mlcDb;    // $DATADIR/mlc
    leveldb::DB* m_myKeyDb;  // $DATADIR/myKey
    leveldb::Cache* m_blockCache; // shared block cache for LevelDB
    const leveldb::FilterPolicy* m_filter; // bloom filter

    // Caches
    StringLruCache m_mlcCache;
    StringLruCache m_myKeyCache;

    // State
    bool m_opened;
};

#endif // NEXALT_MLCDB_H


