////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2011-2025, Armory Technologies, Inc.                        //
//  Distributed under the GNU Affero General Public License (AGPL v3)         //
//  See LICENSE-ATI or http://www.gnu.org/licenses/agpl.html                  //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////
#ifndef LMDBPP_H
#define LMDBPP_H

#include <string>
#include <stdexcept>
#include <vector>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <filesystem>

#include "lmdb.h"

struct MDB_env;
struct MDB_txn;
struct MDB_cursor;

// this exception is thrown for all errors from LMDB
class LMDBException : public std::runtime_error
{
public:
   LMDBException(const std::string&);
};

class NoValue : public LMDBException
{
public:
   NoValue(const std::string&);
};

// a struct that stores a pointer to a memory block
struct CharacterArrayRef
{
   const size_t len;
   const char *data;

   CharacterArrayRef(const size_t, const char*);
   CharacterArrayRef(const size_t, const unsigned char*);
   CharacterArrayRef(const std::string &);
   CharacterArrayRef(const std::vector<char>&);
};

class LMDBEnv;

//one mother-txn per thread
struct LMDBThreadTxInfo;


class LMDB
{
public:
   enum class Mode : int
   {
      ReadWrite=1,
      ReadOnly
   };

private:
   friend class Iterator;

   LMDBEnv* env_ = nullptr;
   unsigned dbi_ = 0;

public:
   class Iterator
   {
      // this class can be used like a C++ iterator,
      // or you can just use isValid() to test for "last item"
      friend class LMDBEnv;
      friend class LMDB;

   private:
      LMDB* db_ = nullptr;
      mutable MDB_cursor* csr_ = nullptr;

      mutable bool hasTx = true;
      bool has_ = false;
      LMDBThreadTxInfo* txnPtr_ = nullptr;
      MDB_val key_, val_;

   private:
      void reset(void);
      void checkHasDb(void) const;
      void checkOk(void) const;
      void openCursor(void);
      Iterator(LMDB*);

   public:
      Iterator(void);
      ~Iterator(void);

      // copying permitted (encouraged!)
      Iterator(const Iterator&);
      Iterator(Iterator&&);
      Iterator& operator=(Iterator&&);
      Iterator& operator=(const Iterator&);

      // Returns true if the key pointed to is identical, or if both iterators
      // are invalid, and false otherwise.
      // returns true if the key pointed to is in different databases
      bool operator==(const Iterator&) const;
      // the inverse
      bool operator!=(const Iterator&) const;

      enum class SeekBy : int
      {
         EQ,
         GE,
         LE
      };

      // move this iterator such that, if the exact key is not found:
      // for e == Seek_EQ
      // The cursor is left as Invalid.
      // for e == Seek::GE
      // The cursor is left pointing to the smallest key in the database that is
      // larger than (key). If the database contains no keys larger than
      // (key), the cursor is left as Invalid.
      void seek(const CharacterArrayRef&, SeekBy e=SeekBy::EQ);

      // is the cursor pointing to a valid location?
      bool isValid(void) const;
      bool isEOF(void) const;

      // advance the cursor
      // the postfix increment operator is not defined for performance reasons
      Iterator& operator++(void);
      void advance();

      Iterator& operator--(void);
      void retreat();

      // seek this iterator to the first sequence
      void toFirst(void);
      void toLast(void);

      // returns the key currently pointed to, if no key is being pointed to
      // std::logic_error is returned (not LSMException). LSMException may
      // be thrown for other reasons. You can avoid logic_error by
      // calling isValid() first
      const MDB_val& key(void) const;

      // returns the value currently pointed to. Exceptions are thrown
      // under the same conditions as key()
      const MDB_val& value(void) const;
   };

   LMDB(void);
   LMDB(LMDBEnv*, const std::string_view& name={});
   ~LMDB(void);

   void open(LMDBEnv*, const std::string_view& name={});
   bool isOpen(void) const;
   void close(void);
   void drop(void);

   // insert a value into the database, replacing
   // the one with a matching key if it is already there
   void insert(
      const CharacterArrayRef&,
      const CharacterArrayRef&
   );

   // delete the entry with the given key, doing nothing
   // if such a key does not exist
   void erase(const CharacterArrayRef&);

   //erases entry and wipes data field
   void wipe(const CharacterArrayRef&);

   // read the value having the given key
   MDB_val value(const CharacterArrayRef&) const;
   
   // read the value having the given key, without copying its
   // data even once. The return object has a pointer to the
   // location in memory
   CharacterArrayRef get_NoCopy(const CharacterArrayRef&) const;

   // create a cursor for scanning the database that points to the first
   // item
   Iterator begin(void) const;

   // creates a cursor that points to an invalid item
   Iterator end(void) const;

   template<class T>
   Iterator find(const T& t) const
   {
      Iterator c = cursor();
      c.seek(t);
      return c;
   }

   // Create an iterator that points to an invalid item.
   // like end(), the iterator can be repositioned to
   // become a valid entry
   Iterator cursor(void) const;

private:
   LMDB(const LMDB&);
   void resize(MDB_env*);
};

struct LMDBThreadTxInfo
{
   MDB_txn *txn=nullptr;

   std::vector<LMDB::Iterator*> iterators;
   unsigned transactionLevel=0;
   LMDB::Mode mode;
};


class LMDBEnv
{
public:
   class Transaction;

private:
   MDB_env *dbenv = nullptr;
   unsigned dbCount_ = 1;

   std::filesystem::path path_;
   std::mutex threadTxMutex_;
   std::unordered_map<std::thread::id, LMDBThreadTxInfo> txForThreads_;

   friend class LMDB;

public:
   class Transaction
   {
      friend class LMDB;

   private:
      LMDBEnv *env=nullptr;
      bool began=false;
      LMDB::Mode mode_;

      std::thread::id tid_;

   public:
      Transaction(void);
      // begin a transaction
      Transaction(LMDBEnv*, LMDB::Mode mode = LMDB::Mode::ReadWrite);
      // commit a transaction if it exists
      ~Transaction(void);

      Transaction(Transaction&&);
      Transaction& operator=(Transaction&&);

      // commit the current transaction, create a new one, and begin it
      void open(LMDBEnv*, LMDB::Mode mode = LMDB::Mode::ReadWrite);

      // commit a transaction, if it exists, doing nothing otherwise.
      // after this function completes, no transaction exists
      void commit(void);
      // rollback the transaction, if it exists, doing nothing otherwise.
      // All modifications made since this transaction began are removed.
      // After this function completes, no transaction exists
      void rollback(void);
      // start a new transaction. If one already exists, do nothing
      void begin(void);

   private:
      Transaction(const Transaction&); // no copies
   };

   LMDBEnv(void);
   LMDBEnv(unsigned);
   ~LMDBEnv(void);

   // open a database by filename
   void open(const std::filesystem::path&, unsigned flags = 0);
   bool isOpen(void) const;

   // close a database, doing nothing if one is presently not open
   void close();

   const std::filesystem::path& getFilename(void) const;
   void setMapSize(size_t);
   void compactCopy(const std::filesystem::path&);
   
private:
   LMDBEnv(const LMDBEnv&); // disallow copy
};


#endif
// kate: indent-width 3; replace-tabs on;

