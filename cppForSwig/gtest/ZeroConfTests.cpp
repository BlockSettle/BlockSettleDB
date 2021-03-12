////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2011-2015, Armory Technologies, Inc.                        //
//  Distributed under the GNU Affero General Public License (AGPL v3)         //
//  See LICENSE-ATI or http://www.gnu.org/licenses/agpl.html                  //
//                                                                            //
//                                                                            //
//  Copyright (C) 2016-2021, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "TestUtils.h"
using namespace std;
using namespace ArmorySigner;
using namespace ArmoryConfig;

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
class ZeroConfTests_FullNode : public ::testing::Test
{
protected:
   BlockDataManagerThread *theBDMt_;
   Clients* clients_;

   void initBDM(void)
   {
      ArmoryConfig::reset();
      DBSettings::setServiceType(SERVICE_UNITTEST);
      ArmoryConfig::parseArgs({
         "--datadir=./fakehomedir",
         "--dbdir=./ldbtestdir",
         "--satoshi-datadir=./blkfiletest",
         "--public",
         "--db-type=DB_FULL",
         "--thread-count=3",
         "--public"
      });

      DBTestUtils::init();
            
      theBDMt_ = new BlockDataManagerThread();
      iface_ = theBDMt_->bdm()->getIFace();

      auto nodePtr = dynamic_pointer_cast<NodeUnitTest>(
         NetworkSettings::bitcoinNodes().first);
      nodePtr->setBlockchain(theBDMt_->bdm()->blockchain());
      nodePtr->setBlockFiles(theBDMt_->bdm()->blockFiles());
      nodePtr->setIface(iface_);

      auto mockedShutdown = [](void)->void {};
      clients_ = new Clients(theBDMt_, mockedShutdown);
   }

   /////////////////////////////////////////////////////////////////////////////
   virtual void SetUp()
   {
      LOGDISABLESTDOUT();
      zeros_ = READHEX("00000000");

      blkdir_ = string("./blkfiletest");
      homedir_ = string("./fakehomedir");
      ldbdir_ = string("./ldbtestdir");

      DBUtils::removeDirectory(blkdir_);
      DBUtils::removeDirectory(homedir_);
      DBUtils::removeDirectory(ldbdir_);

      mkdir(blkdir_ + "/blocks");
      mkdir(homedir_);
      mkdir(ldbdir_);

      // Put the first 5 blocks into the blkdir
      blk0dat_ = BtcUtils::getBlkFilename(blkdir_ + "/blocks", 0);
      TestUtils::setBlocks({ "0", "1", "2", "3", "4", "5" }, blk0dat_);

      wallet1id = "wallet1";
      wallet2id = "wallet2";
      LB1ID = TestChain::lb1B58ID;
      LB2ID = TestChain::lb2B58ID;

      initBDM();

      //first UTXO to hit scrAddrF
      firstUtxoScrAddrF_ = UTXO(500000000, 3, UINT32_MAX, 1, 
         READHEX("9ec8177ca0a4f7aa21ec88a324f236a4d1dce6c610812a90e16febef4603a438"),
         READHEX("76a914d63b766cd342e6f0f7390dd454065e4bbea26b1b88ac"));
   }

   /////////////////////////////////////////////////////////////////////////////
   virtual void TearDown(void)
   {
      if (clients_ != nullptr)
      {
         clients_->exitRequestLoop();
         clients_->shutdown();
      }

      ArmoryConfig::reset();
      delete clients_;
      delete theBDMt_;

      theBDMt_ = nullptr;
      clients_ = nullptr;

      DBUtils::removeDirectory(blkdir_);
      DBUtils::removeDirectory(homedir_);
      DBUtils::removeDirectory("./ldbtestdir");
      
      mkdir("./ldbtestdir");

      ArmoryConfig::reset();

      LOGENABLESTDOUT();
      CLEANUP_ALL_TIMERS();
   }

   LMDBBlockDatabase* iface_;
   BinaryData zeros_;

   string blkdir_;
   string homedir_;
   string ldbdir_;
   string blk0dat_;

   string wallet1id;
   string wallet2id;
   string LB1ID;
   string LB2ID;

   UTXO firstUtxoScrAddrF_;
};

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_FullNode, Load4Blocks_ReloadBDM_ZC_Plus2)
{
   TestUtils::setBlocks({ "0", "1", "2", "3" }, blk0dat_);
   
   theBDMt_->start(DBSettings::initMode());
   auto&& bdvID = DBTestUtils::registerBDV(clients_, BitcoinSettings::getMagicBytes());

   vector<BinaryData> scrAddrVec;
   scrAddrVec.push_back(TestChain::scrAddrA);
   scrAddrVec.push_back(TestChain::scrAddrB);
   scrAddrVec.push_back(TestChain::scrAddrC);
   scrAddrVec.push_back(TestChain::scrAddrE);

   const vector<BinaryData> lb1ScrAddrs
   {
      TestChain::lb1ScrAddr,
      TestChain::lb1ScrAddrP2SH
   };
   const vector<BinaryData> lb2ScrAddrs
   {
      TestChain::lb2ScrAddr,
      TestChain::lb2ScrAddrP2SH
   };

   DBTestUtils::registerWallet(clients_, bdvID, scrAddrVec, "wallet1");
   DBTestUtils::regLockbox(
      clients_, bdvID, lb1ScrAddrs, TestChain::lb1B58ID);
   DBTestUtils::regLockbox(
      clients_, bdvID, lb2ScrAddrs, TestChain::lb2B58ID);

   auto bdvPtr = DBTestUtils::getBDV(clients_, bdvID);

   
   //wait on signals
   DBTestUtils::goOnline(clients_, bdvID);
   DBTestUtils::waitOnBDMReady(clients_, bdvID);
   auto wlt = bdvPtr->getWalletOrLockbox(wallet1id);
   auto wltLB1 = bdvPtr->getWalletOrLockbox(LB1ID);
   auto wltLB2 = bdvPtr->getWalletOrLockbox(LB2ID);

   EXPECT_EQ(DBTestUtils::getTopBlockHeight(iface_, HEADERS), 3);
   EXPECT_EQ(DBTestUtils::getTopBlockHash(iface_, HEADERS), TestChain::blkHash3);
   EXPECT_TRUE(theBDMt_->bdm()->blockchain()->getHeaderByHash(TestChain::blkHash3)->isMainBranch());

   const ScrAddrObj* scrObj;
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50*COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 30*COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 55*COIN);

   uint64_t fullBalance = wlt->getFullBalance();
   uint64_t spendableBalance = wlt->getSpendableBalance(4);
   uint64_t unconfirmedBalance = wlt->getUnconfirmedBalance(4);
   EXPECT_EQ(fullBalance, 165*COIN);
   EXPECT_EQ(spendableBalance, 65*COIN);
   EXPECT_EQ(unconfirmedBalance, 165*COIN);

   scrObj = wltLB1->getScrAddrObjByKey(TestChain::lb1ScrAddr);
   EXPECT_EQ(scrObj->getFullBalance(), 10 * COIN);
   scrObj = wltLB1->getScrAddrObjByKey(TestChain::lb1ScrAddrP2SH);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   scrObj = wltLB2->getScrAddrObjByKey(TestChain::lb2ScrAddr);
   EXPECT_EQ(scrObj->getFullBalance(), 10 * COIN);
   scrObj = wltLB2->getScrAddrObjByKey(TestChain::lb2ScrAddrP2SH);
   EXPECT_EQ(scrObj->getFullBalance(), 5 * COIN);

   EXPECT_EQ(wltLB1->getFullBalance(), 10 * COIN);
   EXPECT_EQ(wltLB2->getFullBalance(), 15 * COIN);

   //restart bdm
   bdvPtr.reset();
   wlt.reset();
   wltLB1.reset();
   wltLB2.reset();

   clients_->exitRequestLoop();
   clients_->shutdown();

   delete clients_;
   delete theBDMt_;

   initBDM();

   theBDMt_->start(DBSettings::initMode());
   bdvID = DBTestUtils::registerBDV(clients_, BitcoinSettings::getMagicBytes());

   DBTestUtils::registerWallet(clients_, bdvID, scrAddrVec, "wallet1");
   DBTestUtils::regLockbox(
      clients_, bdvID, lb1ScrAddrs, TestChain::lb1B58ID);
   DBTestUtils::regLockbox(
      clients_, bdvID, lb2ScrAddrs, TestChain::lb2B58ID);

   bdvPtr = DBTestUtils::getBDV(clients_, bdvID);

   //wait on signals
   DBTestUtils::goOnline(clients_, bdvID);
   DBTestUtils::waitOnBDMReady(clients_, bdvID);
   wlt = bdvPtr->getWalletOrLockbox(wallet1id);
   wltLB1 = bdvPtr->getWalletOrLockbox(LB1ID);
   wltLB2 = bdvPtr->getWalletOrLockbox(LB2ID);

   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50*COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 30*COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 55*COIN);

   fullBalance = wlt->getFullBalance();
   spendableBalance = wlt->getSpendableBalance(4);
   unconfirmedBalance = wlt->getUnconfirmedBalance(4);
   EXPECT_EQ(fullBalance, 165 * COIN);
   EXPECT_EQ(spendableBalance, 65 * COIN);
   EXPECT_EQ(unconfirmedBalance, 165 * COIN);

   scrObj = wltLB1->getScrAddrObjByKey(TestChain::lb1ScrAddr);
   EXPECT_EQ(scrObj->getFullBalance(), 10 * COIN);
   scrObj = wltLB1->getScrAddrObjByKey(TestChain::lb1ScrAddrP2SH);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   scrObj = wltLB2->getScrAddrObjByKey(TestChain::lb2ScrAddr);
   EXPECT_EQ(scrObj->getFullBalance(), 10 * COIN);
   scrObj = wltLB2->getScrAddrObjByKey(TestChain::lb2ScrAddrP2SH);
   EXPECT_EQ(scrObj->getFullBalance(), 5 * COIN);

   EXPECT_EQ(wltLB1->getFullBalance(), 10 * COIN);
   EXPECT_EQ(wltLB2->getFullBalance(), 15 * COIN);

   //add ZC
   BinaryData rawZC(TestChain::zcTxSize);
   FILE *ff = fopen("../reorgTest/ZCtx.tx", "rb");
   fread(rawZC.getPtr(), TestChain::zcTxSize, 1, ff);
   fclose(ff);
   DBTestUtils::ZcVector rawZcVec;
   rawZcVec.push_back(move(rawZC), 0);

   BinaryData rawLBZC(TestChain::lbZCTxSize);
   FILE *flb = fopen("../reorgTest/LBZC.tx", "rb");
   fread(rawLBZC.getPtr(), TestChain::lbZCTxSize, 1, flb);
   fclose(flb);
   DBTestUtils::ZcVector rawLBZcVec;
   rawLBZcVec.push_back(move(rawLBZC), 0);

   DBTestUtils::pushNewZc(theBDMt_, rawZcVec);
   DBTestUtils::waitOnNewZcSignal(clients_, bdvID);

   DBTestUtils::pushNewZc(theBDMt_, rawLBZcVec);
   DBTestUtils::waitOnNewZcSignal(clients_, bdvID);

   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50*COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 20*COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 65*COIN);

   fullBalance = wlt->getFullBalance();
   spendableBalance = wlt->getSpendableBalance(4);
   unconfirmedBalance = wlt->getUnconfirmedBalance(4);
   EXPECT_EQ(fullBalance, 165*COIN);
   EXPECT_EQ(spendableBalance, 35*COIN);
   EXPECT_EQ(unconfirmedBalance, 165*COIN);

   scrObj = wltLB1->getScrAddrObjByKey(TestChain::lb1ScrAddr);
   EXPECT_EQ(scrObj->getFullBalance(), 5 * COIN);
   scrObj = wltLB1->getScrAddrObjByKey(TestChain::lb1ScrAddrP2SH);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   scrObj = wltLB2->getScrAddrObjByKey(TestChain::lb2ScrAddr);
   EXPECT_EQ(scrObj->getFullBalance(), 10 * COIN);
   scrObj = wltLB2->getScrAddrObjByKey(TestChain::lb2ScrAddrP2SH);
   EXPECT_EQ(scrObj->getFullBalance(), 5 * COIN);

   EXPECT_EQ(wltLB1->getFullBalance(), 5 * COIN);
   EXPECT_EQ(wltLB2->getFullBalance(), 15 * COIN);

   //
   TestUtils::setBlocks({ "0", "1", "2", "3", "4", "5" }, blk0dat_);
   DBTestUtils::triggerNewBlockNotification(theBDMt_);
   DBTestUtils::waitOnNewBlockSignal(clients_, bdvID);

   EXPECT_EQ(DBTestUtils::getTopBlockHeight(iface_, HEADERS), 5);
   EXPECT_EQ(DBTestUtils::getTopBlockHash(iface_, HEADERS), TestChain::blkHash5);
   EXPECT_TRUE(theBDMt_->bdm()->blockchain()->getHeaderByHash(TestChain::blkHash5)->isMainBranch());

   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(),  50*COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(),  70*COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(),  20*COIN);

   fullBalance = wlt->getFullBalance();
   spendableBalance = wlt->getSpendableBalance(5);
   unconfirmedBalance = wlt->getUnconfirmedBalance(5);
   EXPECT_EQ(fullBalance, 170*COIN);
   EXPECT_EQ(spendableBalance, 70*COIN);
   EXPECT_EQ(unconfirmedBalance, 170*COIN);

   scrObj = wltLB1->getScrAddrObjByKey(TestChain::lb1ScrAddr);
   EXPECT_EQ(scrObj->getFullBalance(), 5 * COIN);
   scrObj = wltLB1->getScrAddrObjByKey(TestChain::lb1ScrAddrP2SH);
   EXPECT_EQ(scrObj->getFullBalance(), 25 * COIN);
   scrObj = wltLB2->getScrAddrObjByKey(TestChain::lb2ScrAddr);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);
   scrObj = wltLB2->getScrAddrObjByKey(TestChain::lb2ScrAddrP2SH);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);

   EXPECT_EQ(wltLB1->getFullBalance(), 30 * COIN);
   EXPECT_EQ(wltLB2->getFullBalance(), 30 * COIN);

   //cleanup
   bdvPtr.reset();
   wlt.reset();
   wltLB1.reset();
   wltLB2.reset();
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_FullNode, Load3Blocks_ZC_Plus3_TestLedgers)
{
   //copy the first 3 blocks
   TestUtils::setBlocks({ "0", "1", "2", "3" }, blk0dat_);

   theBDMt_->start(DBSettings::initMode());
   auto&& bdvID = DBTestUtils::registerBDV(clients_, BitcoinSettings::getMagicBytes());

   vector<BinaryData> scrAddrVec;
   scrAddrVec.push_back(TestChain::scrAddrA);
   scrAddrVec.push_back(TestChain::scrAddrB);
   scrAddrVec.push_back(TestChain::scrAddrC);
   scrAddrVec.push_back(TestChain::scrAddrE);

   DBTestUtils::registerWallet(clients_, bdvID, scrAddrVec, "wallet1");
   auto bdvPtr = DBTestUtils::getBDV(clients_, bdvID);

   //wait on signals
   DBTestUtils::goOnline(clients_, bdvID);
   DBTestUtils::waitOnBDMReady(clients_, bdvID);
   auto wlt = bdvPtr->getWalletOrLockbox(wallet1id);

   EXPECT_EQ(DBTestUtils::getTopBlockHeight(iface_, HEADERS), 3);
   EXPECT_EQ(DBTestUtils::getTopBlockHash(iface_, HEADERS), TestChain::blkHash3);
   EXPECT_TRUE(theBDMt_->bdm()->blockchain()->getHeaderByHash(TestChain::blkHash3)->isMainBranch());

   const ScrAddrObj* scrObj;
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50*COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 30*COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 55*COIN);

   uint64_t fullBalance = wlt->getFullBalance();
   uint64_t spendableBalance = wlt->getSpendableBalance(3);
   uint64_t unconfirmedBalance = wlt->getUnconfirmedBalance(3);
   EXPECT_EQ(fullBalance, 165 * COIN);
   EXPECT_EQ(spendableBalance, 65 * COIN);
   EXPECT_EQ(unconfirmedBalance, 165 * COIN);

   //add ZC
   auto&& ZC1 = TestUtils::getTx(5, 1); //block 5, tx 1
   auto&& ZChash1 = BtcUtils::getHash256(ZC1);

   DBTestUtils::ZcVector rawZcVec;
   rawZcVec.push_back(ZC1, 1300000000);

   DBTestUtils::pushNewZc(theBDMt_, rawZcVec);
   DBTestUtils::waitOnNewZcSignal(clients_, bdvID);

   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50*COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 65*COIN);

   {
      //check scrAddr ledger before checking balance to make sure fetching 
      //ledgers does not corrupt the scrAddrObj txio map
      scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
      EXPECT_EQ(scrObj->getFullBalance(), 20*COIN);
      auto&& leSA = DBTestUtils::getLedgerEntryFromAddr(
         (ScrAddrObj*)scrObj, ZChash1);
      //EXPECT_EQ(leSA.getTxTime(), 1300000000);
      EXPECT_EQ(leSA.getValue(), -1000000000);
      EXPECT_EQ(leSA.getBlockNum(), UINT32_MAX);
      EXPECT_EQ(scrObj->getFullBalance(), 20 * COIN);
   }


   fullBalance = wlt->getFullBalance();
   spendableBalance = wlt->getSpendableBalance(4);
   unconfirmedBalance = wlt->getUnconfirmedBalance(4);
   EXPECT_EQ(fullBalance, 165 * COIN);
   EXPECT_EQ(spendableBalance, 35 * COIN);
   EXPECT_EQ(unconfirmedBalance, 165 * COIN);

   //check ledger for ZC
   auto&& le = DBTestUtils::getLedgerEntryFromWallet(wlt, ZChash1);
   //EXPECT_EQ(le.getTxTime(), 1300000000);
   EXPECT_EQ(le.getValue(),  3000000000);
   EXPECT_EQ(le.getBlockNum(), UINT32_MAX);

   //pull ZC from DB, verify it's carrying the proper data
   auto&& dbtx = 
      iface_->beginTransaction(ZERO_CONF, LMDB::ReadOnly);
   StoredTx zcStx;
   BinaryData zcKey = WRITE_UINT16_BE(0xFFFF);
   zcKey.append(WRITE_UINT32_LE(0));

   EXPECT_EQ(iface_->getStoredZcTx(zcStx, zcKey), true);
   EXPECT_EQ(zcStx.thisHash_, ZChash1);
   EXPECT_EQ(zcStx.numBytes_ , TestChain::zcTxSize);
   EXPECT_EQ(zcStx.fragBytes_, 190);
   EXPECT_EQ(zcStx.numTxOut_, 2);
   EXPECT_EQ(zcStx.stxoMap_.begin()->second.getValue(), 10 * COIN);

   //check ZChash in DB
   {
      auto ss = theBDMt_->bdm()->zeroConfCont()->getSnapshot();
      EXPECT_EQ(ss->getHashForKey(zcKey), ZChash1);
   }

   dbtx.reset();

   //restart bdm
   bdvPtr.reset();
   wlt.reset();

   clients_->exitRequestLoop();
   clients_->shutdown();

   delete clients_;
   delete theBDMt_;

   initBDM();

   theBDMt_->start(DBSettings::initMode());
   bdvID = DBTestUtils::registerBDV(clients_, BitcoinSettings::getMagicBytes());

   scrAddrVec.pop_back();
   DBTestUtils::registerWallet(clients_, bdvID, scrAddrVec, "wallet1");
   bdvPtr = DBTestUtils::getBDV(clients_, bdvID);

   //wait on signals
   DBTestUtils::goOnline(clients_, bdvID);
   DBTestUtils::waitOnBDMReady(clients_, bdvID);
   wlt = bdvPtr->getWalletOrLockbox(wallet1id);

   //add 5th block
   TestUtils::setBlocks({ "0", "1", "2", "3", "4" }, blk0dat_);
   DBTestUtils::triggerNewBlockNotification(theBDMt_);
   DBTestUtils::waitOnNewBlockSignal(clients_, bdvID);

   EXPECT_EQ(DBTestUtils::getTopBlockHeight(iface_, HEADERS), 4);
   EXPECT_EQ(DBTestUtils::getTopBlockHash(iface_, HEADERS), TestChain::blkHash4);
   EXPECT_TRUE(theBDMt_->bdm()->blockchain()->getHeaderByHash(TestChain::blkHash4)->isMainBranch());

   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50*COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 20*COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 20*COIN);

   fullBalance = wlt->getFullBalance();
   spendableBalance = wlt->getSpendableBalance(5);
   unconfirmedBalance = wlt->getUnconfirmedBalance(5);
   EXPECT_EQ(fullBalance, 90 * COIN);
   EXPECT_EQ(spendableBalance, 10 * COIN);
   EXPECT_EQ(unconfirmedBalance, 90 * COIN);

   dbtx = move(
      iface_->beginTransaction(ZERO_CONF, LMDB::ReadOnly));
   StoredTx zcStx3;

   EXPECT_EQ(iface_->getStoredZcTx(zcStx3, zcKey), true);
   EXPECT_EQ(zcStx3.thisHash_, ZChash1);
   EXPECT_EQ(zcStx3.numBytes_, TestChain::zcTxSize);
   EXPECT_EQ(zcStx3.fragBytes_, 190); // Not sure how Python can get this value
   EXPECT_EQ(zcStx3.numTxOut_, 2);
   EXPECT_EQ(zcStx3.stxoMap_.begin()->second.getValue(), 10 * COIN);

   dbtx.reset();

   //add 6th block
   TestUtils::setBlocks({ "0", "1", "2", "3", "4", "5" }, blk0dat_);
   DBTestUtils::triggerNewBlockNotification(theBDMt_);
   DBTestUtils::waitOnNewBlockSignal(clients_, bdvID);

   EXPECT_EQ(DBTestUtils::getTopBlockHeight(iface_, HEADERS), 5);
   EXPECT_EQ(DBTestUtils::getTopBlockHash(iface_, HEADERS), TestChain::blkHash5);
   EXPECT_TRUE(theBDMt_->bdm()->blockchain()->getHeaderByHash(TestChain::blkHash5)->isMainBranch());

   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 20 * COIN);

   {
      //check scrAddr ledger before checking balance to make sure fetching 
      //ledgers does not corrupt the scrAddrObj txio map
      scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
      auto&& leSA = DBTestUtils::getLedgerEntryFromAddr(
         (ScrAddrObj*)scrObj, ZChash1);
      EXPECT_EQ(leSA.getTxTime(), 1231009513);
      EXPECT_EQ(leSA.getValue(), -1000000000);
      EXPECT_EQ(leSA.getBlockNum(), 5);
      EXPECT_EQ(scrObj->getFullBalance(), 70 * COIN);
   }

   fullBalance = wlt->getFullBalance();
   spendableBalance = wlt->getSpendableBalance(5);
   unconfirmedBalance = wlt->getUnconfirmedBalance(5);
   EXPECT_EQ(fullBalance, 140 * COIN);
   EXPECT_EQ(spendableBalance, 40 * COIN);
   EXPECT_EQ(unconfirmedBalance, 140 * COIN);

   le = DBTestUtils::getLedgerEntryFromWallet(wlt, ZChash1);
   EXPECT_EQ(le.getTxTime(), 1231009513);
   EXPECT_EQ(le.getValue(), 3000000000);
   EXPECT_EQ(le.getBlockNum(), 5);

   //Tx is now in a block, ZC should be gone from DB
   dbtx = move(
      iface_->beginTransaction(ZERO_CONF, LMDB::ReadWrite));
   StoredTx zcStx4;

   EXPECT_EQ(iface_->getStoredZcTx(zcStx4, zcKey), false);
   dbtx.reset();
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_FullNode, Load3Blocks_ZCchain)
{
   //copy the first 3 blocks
   TestUtils::setBlocks({ "0", "1", "2" }, blk0dat_);

   //get ZCs
   auto&& ZC1 = TestUtils::getTx(3, 4); //block 3, tx 4
   auto&& ZC2 = TestUtils::getTx(5, 1); //block 5, tx 1

   auto&& ZChash1 = BtcUtils::getHash256(ZC1);
   auto&& ZChash2 = BtcUtils::getHash256(ZC2);

   DBTestUtils::ZcVector zc1Vec;
   DBTestUtils::ZcVector zc2Vec;
   zc1Vec.push_back(move(ZC1), 1400000000);
   zc2Vec.push_back(move(ZC2), 1500000000);

   theBDMt_->start(DBSettings::initMode());
   auto&& bdvID = DBTestUtils::registerBDV(clients_, BitcoinSettings::getMagicBytes());

   vector<BinaryData> scrAddrVec;
   scrAddrVec.push_back(TestChain::scrAddrA);
   scrAddrVec.push_back(TestChain::scrAddrB);
   scrAddrVec.push_back(TestChain::scrAddrC);

   const vector<BinaryData> lb1ScrAddrs
   {
      TestChain::lb1ScrAddr,
      TestChain::lb1ScrAddrP2SH
   };
   const vector<BinaryData> lb2ScrAddrs
   {
      TestChain::lb2ScrAddr,
      TestChain::lb2ScrAddrP2SH
   };

   DBTestUtils::registerWallet(clients_, bdvID, scrAddrVec, "wallet1");
   DBTestUtils::regLockbox(
      clients_, bdvID, lb1ScrAddrs, TestChain::lb1B58ID);
   DBTestUtils::regLockbox(
      clients_, bdvID, lb2ScrAddrs, TestChain::lb2B58ID);

   auto bdvPtr = DBTestUtils::getBDV(clients_, bdvID);


   //wait on signals
   DBTestUtils::goOnline(clients_, bdvID);
   DBTestUtils::waitOnBDMReady(clients_, bdvID);
   auto wlt = bdvPtr->getWalletOrLockbox(wallet1id);
   auto wltLB1 = bdvPtr->getWalletOrLockbox(LB1ID);
   auto wltLB2 = bdvPtr->getWalletOrLockbox(LB2ID);

   EXPECT_EQ(DBTestUtils::getTopBlockHeight(iface_, HEADERS), 2);
   EXPECT_EQ(DBTestUtils::getTopBlockHash(iface_, HEADERS), TestChain::blkHash2);
   EXPECT_TRUE(theBDMt_->bdm()->blockchain()->getHeaderByHash(TestChain::blkHash2)->isMainBranch());

   const ScrAddrObj* scrObj;
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 55 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);

   uint64_t fullBalance = wlt->getFullBalance();
   uint64_t spendableBalance = wlt->getSpendableBalance(3);
   uint64_t unconfirmedBalance = wlt->getUnconfirmedBalance(3);
   EXPECT_EQ(fullBalance, 105 * COIN);
   EXPECT_EQ(spendableBalance, 5 * COIN);
   EXPECT_EQ(unconfirmedBalance, 105 * COIN);

   //add first ZC
   DBTestUtils::pushNewZc(theBDMt_, zc1Vec);
   DBTestUtils::waitOnNewZcSignal(clients_, bdvID);

   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);

   fullBalance = wlt->getFullBalance();
   spendableBalance = wlt->getSpendableBalance(3);
   unconfirmedBalance = wlt->getUnconfirmedBalance(3);
   EXPECT_EQ(fullBalance, 80 * COIN);
   EXPECT_EQ(spendableBalance, 0 * COIN);
   EXPECT_EQ(unconfirmedBalance, 80 * COIN);

   auto&& le = DBTestUtils::getLedgerEntryFromWallet(wlt, ZChash1);
   //EXPECT_EQ(le.getTxTime(), 1400000000);
   EXPECT_EQ(le.getValue(), -25 * COIN);
   EXPECT_EQ(le.getBlockNum(), UINT32_MAX);
   EXPECT_FALSE(le.isChainedZC());

   //add second ZC
   DBTestUtils::pushNewZc(theBDMt_, zc2Vec);
   DBTestUtils::waitOnNewZcSignal(clients_, bdvID);

   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 20 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 10 * COIN);

   fullBalance = wlt->getFullBalance();
   spendableBalance = wlt->getSpendableBalance(3);
   unconfirmedBalance = wlt->getUnconfirmedBalance(3);
   EXPECT_EQ(fullBalance, 80 * COIN);
   EXPECT_EQ(spendableBalance, 0 * COIN);
   EXPECT_EQ(unconfirmedBalance, 80 * COIN);

   le = DBTestUtils::getLedgerEntryFromWallet(wlt, ZChash1);
   //EXPECT_EQ(le.getTxTime(), 1400000000);
   EXPECT_EQ(le.getValue(), -25 * COIN);
   EXPECT_EQ(le.getBlockNum(), UINT32_MAX);
   EXPECT_FALSE(le.isChainedZC());   

   le = DBTestUtils::getLedgerEntryFromWallet(wlt, ZChash2);
   //EXPECT_EQ(le.getTxTime(), 1500000000);
   EXPECT_EQ(le.getValue(), 30 * COIN);
   EXPECT_EQ(le.getBlockNum(), UINT32_MAX);
   EXPECT_TRUE(le.isChainedZC());

   //add 4th block
   TestUtils::setBlocks({ "0", "1", "2", "3" }, blk0dat_);
   DBTestUtils::triggerNewBlockNotification(theBDMt_);
   DBTestUtils::waitOnNewBlockSignal(clients_, bdvID);

   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 20 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 65 * COIN);

   fullBalance = wlt->getFullBalance();
   spendableBalance = wlt->getSpendableBalance(3);
   unconfirmedBalance = wlt->getUnconfirmedBalance(3);
   EXPECT_EQ(fullBalance, 135 * COIN);
   EXPECT_EQ(spendableBalance, 5 * COIN);
   EXPECT_EQ(unconfirmedBalance, 135 * COIN);

   le = DBTestUtils::getLedgerEntryFromWallet(wlt, ZChash1);
   EXPECT_EQ(le.getTxTime(), 1231008309);
   EXPECT_EQ(le.getValue(), -25 * COIN);
   EXPECT_EQ(le.getBlockNum(), 3);
   EXPECT_FALSE(le.isChainedZC());

   le = DBTestUtils::getLedgerEntryFromWallet(wlt, ZChash2);
   //EXPECT_EQ(le.getTxTime(), 1500000000);
   EXPECT_EQ(le.getValue(), 30 * COIN);
   EXPECT_EQ(le.getBlockNum(), UINT32_MAX);
   EXPECT_FALSE(le.isChainedZC());

   //add 5th and 6th block
   TestUtils::setBlocks({ "0", "1", "2", "3", "4", "5" }, blk0dat_);
   DBTestUtils::triggerNewBlockNotification(theBDMt_);
   DBTestUtils::waitOnNewBlockSignal(clients_, bdvID);

   EXPECT_EQ(DBTestUtils::getTopBlockHeight(iface_, HEADERS), 5);
   EXPECT_EQ(DBTestUtils::getTopBlockHash(iface_, HEADERS), TestChain::blkHash5);
   EXPECT_TRUE(theBDMt_->bdm()->blockchain()->getHeaderByHash(TestChain::blkHash5)->isMainBranch());

   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 70 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 20 * COIN);

   fullBalance = wlt->getFullBalance();
   spendableBalance = wlt->getSpendableBalance(5);
   unconfirmedBalance = wlt->getUnconfirmedBalance(5);
   EXPECT_EQ(fullBalance, 140 * COIN);
   EXPECT_EQ(spendableBalance, 40 * COIN);
   EXPECT_EQ(unconfirmedBalance, 140 * COIN);

   le = DBTestUtils::getLedgerEntryFromWallet(wlt, ZChash2);
   EXPECT_EQ(le.getTxTime(), 1231009513);
   EXPECT_EQ(le.getValue(), 30 * COIN);
   EXPECT_EQ(le.getBlockNum(), 5);
   EXPECT_FALSE(le.isChainedZC());
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_FullNode, Load3Blocks_RBF)
{
   //get ZCs
   auto&& ZC1 = TestUtils::getTx(5, 1); //block 5, tx 1
   auto&& ZChash1 = BtcUtils::getHash256(ZC1);

   Tx zcTx1(ZC1);
   OutPoint op0 = zcTx1.getTxInCopy(0).getOutPoint();

   BinaryData rawRBF, spendRBF;

   {
      //build RBF enabled mock ZC, spend first input of 5|1, to bogus address
      BinaryWriter bw;
      bw.put_uint32_t(1); //version number

      //input
      bw.put_var_int(1); //1 input, no need to complicate this
      bw.put_BinaryData(op0.getTxHash()); //hash of tx we are spending
      bw.put_uint32_t(op0.getTxOutIndex()); //output id
      bw.put_var_int(0); //empty script, not like we are checking sigs anyways
      bw.put_uint32_t(1); //flagged sequence number

      //spend script, classic P2PKH
      BinaryData fakeAddr = 
         READHEX("0101010101010101010101010101010101010101");
      BinaryWriter spendScript;
      spendScript.put_uint8_t(OP_DUP);
      spendScript.put_uint8_t(OP_HASH160);
      spendScript.put_var_int(fakeAddr.getSize());
      spendScript.put_BinaryData(fakeAddr); //bogus address
      spendScript.put_uint8_t(OP_EQUALVERIFY);
      spendScript.put_uint8_t(OP_CHECKSIG);

      auto& spendScriptbd = spendScript.getData();

      //output
      bw.put_var_int(1); //txout count
      bw.put_uint64_t(30 * COIN); //value
      bw.put_var_int(spendScriptbd.getSize()); //script length
      bw.put_BinaryData(spendScriptbd); //spend script

      //locktime
      bw.put_uint32_t(UINT32_MAX);

      rawRBF = bw.getData();
   }

   {
      //build bogus ZC spending RBF to self instead
      BinaryWriter bw;
      bw.put_uint32_t(1); //version number

      //input
      bw.put_var_int(1); 
      bw.put_BinaryData(op0.getTxHash());
      bw.put_uint32_t(op0.getTxOutIndex());
      bw.put_var_int(0);
      bw.put_uint32_t(1);

      //spend script, classic P2PKH
      BinaryWriter spendScript;
      spendScript.put_uint8_t(OP_DUP);
      spendScript.put_uint8_t(OP_HASH160);
      spendScript.put_var_int(TestChain::addrA.getSize());
      spendScript.put_BinaryData(TestChain::addrA); //spend back to self
      spendScript.put_uint8_t(OP_EQUALVERIFY);
      spendScript.put_uint8_t(OP_CHECKSIG);

      auto& spendScriptbd = spendScript.getData();

      //output
      bw.put_var_int(1);
      bw.put_uint64_t(30 * COIN); //value
      bw.put_var_int(spendScriptbd.getSize()); //script length
      bw.put_BinaryData(spendScriptbd); //spend script

      //locktime
      bw.put_uint32_t(UINT32_MAX);

      spendRBF = bw.getData();
   }

   auto&& RBFhash       = BtcUtils::getHash256(rawRBF);
   auto&& spendRBFhash  = BtcUtils::getHash256(spendRBF);

   DBTestUtils::ZcVector rawRBFVec;
   DBTestUtils::ZcVector spendRBFVec;

   rawRBFVec.push_back(move(rawRBF), 1400000000);
   spendRBFVec.push_back(move(spendRBF), 1500000000);

   //copy the first 4 blocks
   TestUtils::setBlocks({ "0", "1", "2", "3" }, blk0dat_);

   theBDMt_->start(DBSettings::initMode());
   auto&& bdvID = DBTestUtils::registerBDV(clients_, BitcoinSettings::getMagicBytes());

   vector<BinaryData> scrAddrVec;
   scrAddrVec.push_back(TestChain::scrAddrA);
   scrAddrVec.push_back(TestChain::scrAddrB);
   scrAddrVec.push_back(TestChain::scrAddrC);

   const vector<BinaryData> lb1ScrAddrs
   {
      TestChain::lb1ScrAddr,
      TestChain::lb1ScrAddrP2SH
   };
   const vector<BinaryData> lb2ScrAddrs
   {
      TestChain::lb2ScrAddr,
      TestChain::lb2ScrAddrP2SH
   };

   DBTestUtils::registerWallet(clients_, bdvID, scrAddrVec, "wallet1");
   DBTestUtils::regLockbox(
      clients_, bdvID, lb1ScrAddrs, TestChain::lb1B58ID);
   DBTestUtils::regLockbox(
      clients_, bdvID, lb2ScrAddrs, TestChain::lb2B58ID);

   auto bdvPtr = DBTestUtils::getBDV(clients_, bdvID);


   //wait on signals
   DBTestUtils::goOnline(clients_, bdvID);
   DBTestUtils::waitOnBDMReady(clients_, bdvID);
   auto wlt = bdvPtr->getWalletOrLockbox(wallet1id);
   auto wltLB1 = bdvPtr->getWalletOrLockbox(LB1ID);
   auto wltLB2 = bdvPtr->getWalletOrLockbox(LB2ID);

   const ScrAddrObj* scrObj;
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 55 * COIN);

   uint64_t fullBalance = wlt->getFullBalance();
   uint64_t spendableBalance = wlt->getSpendableBalance(3);
   uint64_t unconfirmedBalance = wlt->getUnconfirmedBalance(3);
   EXPECT_EQ(fullBalance, 135 * COIN);
   EXPECT_EQ(spendableBalance, 35 * COIN);
   EXPECT_EQ(unconfirmedBalance, 135 * COIN);

   //add RBF ZC
   DBTestUtils::pushNewZc(theBDMt_, rawRBFVec);
   DBTestUtils::waitOnNewZcSignal(clients_, bdvID);

   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 55 * COIN);

   fullBalance = wlt->getFullBalance();
   spendableBalance = wlt->getSpendableBalance(3);
   unconfirmedBalance = wlt->getUnconfirmedBalance(3);
   EXPECT_EQ(fullBalance, 105 * COIN);
   EXPECT_EQ(spendableBalance, 5 * COIN);
   EXPECT_EQ(unconfirmedBalance, 105 * COIN);

   //check ledger
   auto&& le = DBTestUtils::getLedgerEntryFromWallet(wlt, RBFhash);
   //EXPECT_EQ(le.getTxTime(), 1400000000);
   EXPECT_EQ(le.getValue(), -30 * COIN);
   EXPECT_EQ(le.getBlockNum(), UINT32_MAX);
   EXPECT_TRUE(le.isOptInRBF());

   //replace it
   DBTestUtils::pushNewZc(theBDMt_, spendRBFVec);
   DBTestUtils::waitOnNewZcSignal(clients_, bdvID);

   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 80 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 55 * COIN);

   fullBalance = wlt->getFullBalance();
   spendableBalance = wlt->getSpendableBalance(3);
   unconfirmedBalance = wlt->getUnconfirmedBalance(3);
   EXPECT_EQ(fullBalance, 135 * COIN);
   EXPECT_EQ(spendableBalance, 5 * COIN);
   EXPECT_EQ(unconfirmedBalance, 135 * COIN);

   //verify replacement in ledgers
   le = DBTestUtils::getLedgerEntryFromWallet(wlt, RBFhash);
   EXPECT_EQ(le.getTxHash(), BtcUtils::EmptyHash_);

   le = DBTestUtils::getLedgerEntryFromWallet(wlt, spendRBFhash);
   //EXPECT_EQ(le.getTxTime(), 1500000000);
   EXPECT_EQ(le.getValue(), 30 * COIN);
   EXPECT_EQ(le.getBlockNum(), UINT32_MAX);
   EXPECT_TRUE(le.isOptInRBF());

   //add last blocks
   TestUtils::setBlocks({ "0", "1", "2", "3", "4", "5" }, blk0dat_);
   DBTestUtils::triggerNewBlockNotification(theBDMt_);
   DBTestUtils::waitOnNewBlockSignal(clients_, bdvID);

   EXPECT_EQ(DBTestUtils::getTopBlockHeight(iface_, HEADERS), 5);
   EXPECT_EQ(DBTestUtils::getTopBlockHash(iface_, HEADERS), TestChain::blkHash5);
   EXPECT_TRUE(theBDMt_->bdm()->blockchain()->getHeaderByHash(TestChain::blkHash5)->isMainBranch());

   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 70 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 20 * COIN);

   fullBalance = wlt->getFullBalance();
   spendableBalance = wlt->getSpendableBalance(5);
   unconfirmedBalance = wlt->getUnconfirmedBalance(5);
   EXPECT_EQ(fullBalance, 140 * COIN);
   EXPECT_EQ(spendableBalance, 40 * COIN);
   EXPECT_EQ(unconfirmedBalance, 140 * COIN);
   
   //verify replacement ZC is invalid now
   le = DBTestUtils::getLedgerEntryFromWallet(wlt, spendRBFhash);
   EXPECT_EQ(le.getTxHash(), BtcUtils::EmptyHash_);
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_FullNode, Load4Blocks_ZC_GetUtxos)
{
   TestUtils::setBlocks({ "0", "1", "2", "3" }, blk0dat_);

   theBDMt_->start(DBSettings::initMode());
   auto&& bdvID = DBTestUtils::registerBDV(clients_, BitcoinSettings::getMagicBytes());

   vector<BinaryData> scrAddrVec;
   scrAddrVec.push_back(TestChain::scrAddrA);
   scrAddrVec.push_back(TestChain::scrAddrB);
   scrAddrVec.push_back(TestChain::scrAddrC);
   scrAddrVec.push_back(TestChain::scrAddrE);

   const vector<BinaryData> lb1ScrAddrs
   {
      TestChain::lb1ScrAddr,
      TestChain::lb1ScrAddrP2SH
   };
   const vector<BinaryData> lb2ScrAddrs
   {
      TestChain::lb2ScrAddr,
      TestChain::lb2ScrAddrP2SH
   };

   DBTestUtils::registerWallet(clients_, bdvID, scrAddrVec, "wallet1");
   DBTestUtils::regLockbox(
      clients_, bdvID, lb1ScrAddrs, TestChain::lb1B58ID);
   DBTestUtils::regLockbox(
      clients_, bdvID, lb2ScrAddrs, TestChain::lb2B58ID);

   auto bdvPtr = DBTestUtils::getBDV(clients_, bdvID);

   //wait on signals
   DBTestUtils::goOnline(clients_, bdvID);
   DBTestUtils::waitOnBDMReady(clients_, bdvID);
   auto wlt = bdvPtr->getWalletOrLockbox(wallet1id);
   auto wltLB1 = bdvPtr->getWalletOrLockbox(LB1ID);
   auto wltLB2 = bdvPtr->getWalletOrLockbox(LB2ID);

   EXPECT_EQ(DBTestUtils::getTopBlockHeight(iface_, HEADERS), 3);
   EXPECT_EQ(DBTestUtils::getTopBlockHash(iface_, HEADERS), TestChain::blkHash3);
   EXPECT_TRUE(theBDMt_->bdm()->blockchain()->getHeaderByHash(TestChain::blkHash3)->isMainBranch());

   const ScrAddrObj* scrObj;
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 55 * COIN);

   uint64_t fullBalance = wlt->getFullBalance();
   uint64_t spendableBalance = wlt->getSpendableBalance(4);
   uint64_t unconfirmedBalance = wlt->getUnconfirmedBalance(4);
   EXPECT_EQ(fullBalance, 165 * COIN);
   EXPECT_EQ(spendableBalance, 65 * COIN);
   EXPECT_EQ(unconfirmedBalance, 165 * COIN);

   scrObj = wltLB1->getScrAddrObjByKey(TestChain::lb1ScrAddr);
   EXPECT_EQ(scrObj->getFullBalance(), 10 * COIN);
   scrObj = wltLB1->getScrAddrObjByKey(TestChain::lb1ScrAddrP2SH);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   scrObj = wltLB2->getScrAddrObjByKey(TestChain::lb2ScrAddr);
   EXPECT_EQ(scrObj->getFullBalance(), 10 * COIN);
   scrObj = wltLB2->getScrAddrObjByKey(TestChain::lb2ScrAddrP2SH);
   EXPECT_EQ(scrObj->getFullBalance(), 5 * COIN);

   EXPECT_EQ(wltLB1->getFullBalance(), 10 * COIN);
   EXPECT_EQ(wltLB2->getFullBalance(), 15 * COIN);


   //add ZC
   BinaryData rawZC(TestChain::zcTxSize);
   FILE *ff = fopen("../reorgTest/ZCtx.tx", "rb");
   fread(rawZC.getPtr(), TestChain::zcTxSize, 1, ff);
   fclose(ff);

   BinaryData rawLBZC(TestChain::lbZCTxSize);
   FILE *flb = fopen("../reorgTest/LBZC.tx", "rb");
   fread(rawLBZC.getPtr(), TestChain::lbZCTxSize, 1, flb);
   fclose(flb);

   DBTestUtils::ZcVector zcVec;
   zcVec.push_back(move(rawZC), 0);
   zcVec.push_back(move(rawLBZC), 0);

   DBTestUtils::pushNewZc(theBDMt_, zcVec);
   DBTestUtils::waitOnNewZcSignal(clients_, bdvID);

   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 20 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 65 * COIN);

   fullBalance = wlt->getFullBalance();
   spendableBalance = wlt->getSpendableBalance(4);
   unconfirmedBalance = wlt->getUnconfirmedBalance(4);
   EXPECT_EQ(fullBalance, 165 * COIN);
   EXPECT_EQ(spendableBalance, 35 * COIN);
   EXPECT_EQ(unconfirmedBalance, 165 * COIN);

   scrObj = wltLB1->getScrAddrObjByKey(TestChain::lb1ScrAddr);
   EXPECT_EQ(scrObj->getFullBalance(), 5 * COIN);
   scrObj = wltLB1->getScrAddrObjByKey(TestChain::lb1ScrAddrP2SH);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   scrObj = wltLB2->getScrAddrObjByKey(TestChain::lb2ScrAddr);
   EXPECT_EQ(scrObj->getFullBalance(), 10 * COIN);
   scrObj = wltLB2->getScrAddrObjByKey(TestChain::lb2ScrAddrP2SH);
   EXPECT_EQ(scrObj->getFullBalance(), 5 * COIN);

   EXPECT_EQ(wltLB1->getFullBalance(), 5 * COIN);
   EXPECT_EQ(wltLB2->getFullBalance(), 15 * COIN);

   //get utxos with zc
   spendableBalance = wlt->getSpendableBalance(4);
   auto&& utxoVec = wlt->getSpendableTxOutListForValue(UINT64_MAX);

   uint64_t totalUtxoVal = 0;
   for (auto& utxo : utxoVec)
      totalUtxoVal += utxo.getValue();

   EXPECT_EQ(spendableBalance, totalUtxoVal);
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_FullNode, Replace_ZC_Test)
{
   //create spender lambda
   auto getSpenderPtr = [](const UnspentTxOut& utxo)->shared_ptr<ScriptSpender>
   {
      UTXO entry(utxo.value_, utxo.txHeight_, utxo.txIndex_, utxo.txOutIndex_,
         move(utxo.txHash_), move(utxo.script_));

      auto spender = make_shared<ScriptSpender>(entry);
      spender->setSequence(UINT32_MAX - 2);

      return spender;
   };

   BinaryData ZCHash1, ZCHash2, ZCHash3, ZCHash4;

   //
   TestUtils::setBlocks({ "0", "1", "2", "3" }, blk0dat_);

   theBDMt_->start(DBSettings::initMode());
   auto&& bdvID = DBTestUtils::registerBDV(clients_, BitcoinSettings::getMagicBytes());

   vector<BinaryData> scrAddrVec;
   scrAddrVec.push_back(TestChain::scrAddrA);
   scrAddrVec.push_back(TestChain::scrAddrB);
   scrAddrVec.push_back(TestChain::scrAddrC);
   scrAddrVec.push_back(TestChain::scrAddrD);
   scrAddrVec.push_back(TestChain::scrAddrE);

   //// create assetWlt ////

   //create a root private key
   auto&& wltRoot = CryptoPRNG::generateRandom(32);
   auto assetWlt = AssetWallet_Single::createFromPrivateRoot_Armory135(
      homedir_,
      move(wltRoot), //root as a r value
      {},
      SecureBinaryData(),
      SecureBinaryData(),
      10); //set lookup computation to 5 entries
      
   //register with db
   vector<BinaryData> addrVec;

   auto hashSet = assetWlt->getAddrHashSet();
   vector<BinaryData> hashVec;
   hashVec.insert(hashVec.begin(), hashSet.begin(), hashSet.end());

   DBTestUtils::registerWallet(clients_, bdvID, hashVec, assetWlt->getID());
   DBTestUtils::registerWallet(clients_, bdvID, scrAddrVec, "wallet1");

   auto bdvPtr = DBTestUtils::getBDV(clients_, bdvID);

   //wait on signals
   DBTestUtils::goOnline(clients_, bdvID);
   DBTestUtils::waitOnBDMReady(clients_, bdvID);
   auto wlt = bdvPtr->getWalletOrLockbox(wallet1id);
   auto dbAssetWlt = bdvPtr->getWalletOrLockbox(assetWlt->getID());

   //check balances
   const ScrAddrObj* scrObj;
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 55 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrD);
   EXPECT_EQ(scrObj->getFullBalance(), 5 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrE);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);

   //check new wallet balances
   for (auto& scripthash : hashSet)
   {
      scrObj = dbAssetWlt->getScrAddrObjByKey(scripthash);
      EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   }

   {
      ////spend 27 from wlt to assetWlt's first 2 unused addresses
      ////send rest back to scrAddrA

      auto spendVal = 27 * COIN;
      Signer signer;

      //instantiate resolver feed overloaded object
      auto feed = make_shared<ResolverUtils::TestResolverFeed>();
      feed->addPrivKey(TestChain::privKeyAddrB);
      feed->addPrivKey(TestChain::privKeyAddrC);
      feed->addPrivKey(TestChain::privKeyAddrD);
      feed->addPrivKey(TestChain::privKeyAddrE);

      //get utxo list for spend value
      auto&& unspentVec = wlt->getSpendableTxOutListForValue(spendVal);

      vector<UnspentTxOut> utxoVec;
      uint64_t tval = 0;
      auto utxoIter = unspentVec.begin();
      while (utxoIter != unspentVec.end())
      {
         tval += utxoIter->getValue();
         utxoVec.push_back(*utxoIter);

         if (tval > spendVal)
            break;

         ++utxoIter;
      }

      //create script spender objects
      uint64_t total = 0;
      for (auto& utxo : utxoVec)
      {
         total += utxo.getValue();
         signer.addSpender(getSpenderPtr(utxo));
      }

      //spend 12 to first address
      auto addr0 = assetWlt->getNewAddress();
      signer.addRecipient(addr0->getRecipient(12 * COIN));
      addrVec.push_back(addr0->getPrefixedHash());

      //spend 15 to addr 1, use P2PKH
      auto addr1 = assetWlt->getNewAddress();
      signer.addRecipient(addr1->getRecipient(15 * COIN));
      addrVec.push_back(addr1->getPrefixedHash());

      if (total > spendVal)
      {
         //deal with change, no fee
         auto changeVal = total - spendVal;
         auto recipientChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrD.getSliceCopy(1, 20), changeVal);
         signer.addRecipient(recipientChange);
      }

      //sign, verify then broadcast
      signer.setFeed(feed);
      signer.sign();
      EXPECT_TRUE(signer.verify());

      auto rawTx = signer.serializeSignedTx();
      DBTestUtils::ZcVector zcVec;
      zcVec.push_back(rawTx, 14000000);

      ZCHash1 = move(BtcUtils::getHash256(rawTx));
      DBTestUtils::pushNewZc(theBDMt_, zcVec);
      DBTestUtils::waitOnNewZcSignal(clients_, bdvID);
   }

   //check balances
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 55 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrD);
   EXPECT_EQ(scrObj->getFullBalance(), 8 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrE);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);

   //check new wallet balances
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[0]);
   EXPECT_EQ(scrObj->getFullBalance(), 12 * COIN);
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[1]);
   EXPECT_EQ(scrObj->getFullBalance(), 15 * COIN);

   //grab ledger
   auto&& zcledger = DBTestUtils::getLedgerEntryFromWallet(dbAssetWlt, ZCHash1);
   EXPECT_EQ(zcledger.getValue(), 27 * COIN);
   //EXPECT_EQ(zcledger.getTxTime(), 14000000);
   EXPECT_TRUE(zcledger.isOptInRBF());


   {
      ////Double spend the 27
      auto spendVal = 27 * COIN;
      Signer signer2;

      //instantiate resolver feed overloaded object
      auto feed = make_shared<ResolverUtils::TestResolverFeed>();
      feed->addPrivKey(TestChain::privKeyAddrB);
      feed->addPrivKey(TestChain::privKeyAddrC);
      feed->addPrivKey(TestChain::privKeyAddrD);
      feed->addPrivKey(TestChain::privKeyAddrE);

      //get utxo list for spend value
      auto&& unspentVec = wlt->getRBFTxOutList();

      vector<UnspentTxOut> utxoVec;
      uint64_t tval = 0;
      auto utxoIter = unspentVec.begin();
      while (utxoIter != unspentVec.end())
      {
         tval += utxoIter->getValue();
         utxoVec.push_back(*utxoIter);

         if (tval > spendVal)
            break;

         ++utxoIter;
      }

      //create script spender objects
      uint64_t total = 0;
      for (auto& utxo : utxoVec)
      {
         total += utxo.getValue();
         signer2.addSpender(getSpenderPtr(utxo));
      }

      //spend 12 to first address
      auto addr0 = assetWlt->getNewAddress();
      signer2.addRecipient(addr0->getRecipient(12 * COIN));
      addrVec.push_back(addr0->getPrefixedHash());

      //spend 14 to addr 1, use P2PKH
      auto addr1 = assetWlt->getNewAddress();
      signer2.addRecipient(addr1->getRecipient(14 * COIN));
      addrVec.push_back(addr1->getPrefixedHash());

      if (total > spendVal)
      {
         //deal with change, 1 btc fee
         auto changeVal = total - spendVal - 1 * COIN;
         auto recipientChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrD.getSliceCopy(1, 20), changeVal);
         signer2.addRecipient(recipientChange);
      }

      //sign, verify then broadcast
      signer2.setFeed(feed);
      signer2.sign();
      EXPECT_TRUE(signer2.verify());

      auto rawTx = signer2.serializeSignedTx();
      DBTestUtils::ZcVector zcVec2;
      zcVec2.push_back(rawTx, 15000000);

      ZCHash2 = move(BtcUtils::getHash256(rawTx));
      DBTestUtils::pushNewZc(theBDMt_, zcVec2);
      DBTestUtils::waitOnNewZcSignal(clients_, bdvID);
   }

   //check balances
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 55 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrD);
   EXPECT_EQ(scrObj->getFullBalance(), 7 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrE);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);

   //check new wallet balances
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[0]);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[1]);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[2]);
   EXPECT_EQ(scrObj->getFullBalance(), 12 * COIN);
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[3]);
   EXPECT_EQ(scrObj->getFullBalance(), 14 * COIN);

   //grab ledgers

   //first zc should be replaced, hence the ledger should be empty
   auto&& zcledger2 = DBTestUtils::getLedgerEntryFromWallet(dbAssetWlt, ZCHash1);
   EXPECT_EQ(zcledger2.getTxHash(), BtcUtils::EmptyHash_);

   //second zc should be valid
   //grab ledger
   auto&& zcledger3 = DBTestUtils::getLedgerEntryFromWallet(dbAssetWlt, ZCHash2);
   EXPECT_EQ(zcledger3.getValue(), 26 * COIN);
   //EXPECT_EQ(zcledger3.getTxTime(), 15000000);
   EXPECT_TRUE(zcledger3.isOptInRBF());

   //cpfp the first rbf
   {
      ////CPFP the 26
      auto spendVal = 15 * COIN;
      Signer signer3;

      //instantiate resolver feed overloaded object
      auto assetFeed = make_shared<ResolverFeed_AssetWalletSingle>(assetWlt);

      //get utxo list for spend value
      auto&& unspentVec = dbAssetWlt->getSpendableTxOutListZC();

      vector<UnspentTxOut> utxoVec;
      uint64_t tval = 0;
      auto utxoIter = unspentVec.begin();
      while (utxoIter != unspentVec.end())
      {
         tval += utxoIter->getValue();
         utxoVec.push_back(*utxoIter);

         if (tval > spendVal)
            break;

         ++utxoIter;
      }

      //create script spender objects
      uint64_t total = 0;
      for (auto& utxo : utxoVec)
      {
         total += utxo.getValue();
         signer3.addSpender(getSpenderPtr(utxo));
      }

      //spend 4 to first address
      auto addr0 = assetWlt->getNewAddress();
      signer3.addRecipient(addr0->getRecipient(4 * COIN));
      addrVec.push_back(addr0->getPrefixedHash());

      //spend 6 to addr 1, use P2PKH
      auto addr1 = assetWlt->getNewAddress();
      signer3.addRecipient(addr1->getRecipient(6 * COIN));
      addrVec.push_back(addr1->getPrefixedHash());

      if (total > spendVal)
      {
         //deal with change, no fee
         auto changeVal = total - spendVal;
         auto recipientChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrD.getSliceCopy(1, 20), changeVal);
         signer3.addRecipient(recipientChange);
      }

      //sign, verify then broadcast
      {
         auto lock = assetWlt->lockDecryptedContainer();
         signer3.setFeed(assetFeed);
         signer3.sign();
      }
      EXPECT_TRUE(signer3.verify());

      auto rawTx = signer3.serializeSignedTx();
      DBTestUtils::ZcVector zcVec3;
      zcVec3.push_back(rawTx, 16000000);

      ZCHash3 = move(BtcUtils::getHash256(rawTx));
      DBTestUtils::pushNewZc(theBDMt_, zcVec3);
      DBTestUtils::waitOnNewZcSignal(clients_, bdvID);
   }

   //check balances
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 55 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrD);
   EXPECT_EQ(scrObj->getFullBalance(), 18 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrE);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);

   //check new wallet balances
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[0]);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[1]);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[2]);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[3]);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[4]);
   EXPECT_EQ(scrObj->getFullBalance(), 4 * COIN);
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[5]);
   EXPECT_EQ(scrObj->getFullBalance(), 6 * COIN);


   //grab ledgers

   //first zc should be replaced, hence the ledger should be empty
   auto&& zcledger4 = DBTestUtils::getLedgerEntryFromWallet(dbAssetWlt, ZCHash1);
   EXPECT_EQ(zcledger4.getTxHash(), BtcUtils::EmptyHash_);

   //second zc should be valid
   //grab ledger
   auto&& zcledger5 = DBTestUtils::getLedgerEntryFromWallet(dbAssetWlt, ZCHash2);
   EXPECT_EQ(zcledger5.getValue(), 26 * COIN);
   //EXPECT_EQ(zcledger5.getTxTime(), 15000000);
   EXPECT_TRUE(zcledger5.isOptInRBF());

   //third zc should be valid
   //grab ledger
   auto&& zcledger6 = DBTestUtils::getLedgerEntryFromWallet(dbAssetWlt, ZCHash3);
   EXPECT_EQ(zcledger6.getValue(), -16 * COIN);
   //EXPECT_EQ(zcledger6.getTxTime(), 16000000);
   EXPECT_TRUE(zcledger6.isChainedZC());
   EXPECT_TRUE(zcledger6.isOptInRBF());

   //rbf the 2 zc chain dead

   {
      ////Double spend the 27
      auto spendVal = 22 * COIN;
      Signer signer2;

      //instantiate resolver feed overloaded object
      auto feed = make_shared<ResolverUtils::TestResolverFeed>();
      feed->addPrivKey(TestChain::privKeyAddrB);
      feed->addPrivKey(TestChain::privKeyAddrC);
      feed->addPrivKey(TestChain::privKeyAddrD);
      feed->addPrivKey(TestChain::privKeyAddrE);

      //get utxo list for spend value
      auto&& unspentVec = wlt->getRBFTxOutList();

      vector<UnspentTxOut> utxoVec;
      uint64_t tval = 0;
      auto utxoIter = unspentVec.begin();
      while (utxoIter != unspentVec.end())
      {
         tval += utxoIter->getValue();
         utxoVec.push_back(*utxoIter);

         if (tval > spendVal)
            break;

         ++utxoIter;
      }

      //create script spender objects
      uint64_t total = 0;
      for (auto& utxo : utxoVec)
      {
         total += utxo.getValue();
         signer2.addSpender(getSpenderPtr(utxo));
      }

      //spend 12 to first address
      auto addr0 = assetWlt->getNewAddress();
      signer2.addRecipient(addr0->getRecipient(10 * COIN));
      addrVec.push_back(addr0->getPrefixedHash());

      //spend 14 to addr 1, use P2PKH
      auto addr1 = assetWlt->getNewAddress();
      signer2.addRecipient(addr1->getRecipient(12 * COIN));
      addrVec.push_back(addr1->getPrefixedHash());

      if (total > spendVal)
      {
         //deal with change, 1 btc fee
         auto changeVal = total - spendVal - 1 * COIN;
         auto recipientChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrD.getSliceCopy(1, 20), changeVal);
         signer2.addRecipient(recipientChange);
      }

      //sign, verify then broadcast
      signer2.setFeed(feed);
      signer2.sign();
      EXPECT_TRUE(signer2.verify());

      auto rawTx = signer2.serializeSignedTx();
      DBTestUtils::ZcVector zcVec2;
      zcVec2.push_back(rawTx, 17000000);

      ZCHash4 = move(BtcUtils::getHash256(rawTx));
      DBTestUtils::pushNewZc(theBDMt_, zcVec2);
      DBTestUtils::waitOnNewZcSignal(clients_, bdvID);
   }

   //check balances
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 55 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrD);
   EXPECT_EQ(scrObj->getFullBalance(), 12 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrE);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);

   //check new wallet balances
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[0]);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[1]);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[2]);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[3]);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[4]);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[5]);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[6]);
   EXPECT_EQ(scrObj->getFullBalance(), 10 * COIN);
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[7]);
   EXPECT_EQ(scrObj->getFullBalance(), 12 * COIN);


   //grab ledgers

   //first zc should be replaced, hence the ledger should be empty
   auto&& zcledger7 = DBTestUtils::getLedgerEntryFromWallet(dbAssetWlt, ZCHash1);
   EXPECT_EQ(zcledger7.getTxHash(), BtcUtils::EmptyHash_);

   //second zc should be replaced
   auto&& zcledger8 = DBTestUtils::getLedgerEntryFromWallet(dbAssetWlt, ZCHash2);
   EXPECT_EQ(zcledger8.getTxHash(), BtcUtils::EmptyHash_);

   //third zc should be replaced
   auto&& zcledger9 = DBTestUtils::getLedgerEntryFromWallet(dbAssetWlt, ZCHash3);
   EXPECT_EQ(zcledger9.getTxHash(), BtcUtils::EmptyHash_);

   //fourth zc should be valid
   auto&& zcledger10 = DBTestUtils::getLedgerEntryFromWallet(dbAssetWlt, ZCHash4);
   EXPECT_EQ(zcledger10.getValue(), 22 * COIN);
   //EXPECT_EQ(zcledger10.getTxTime(), 17000000);
   EXPECT_FALSE(zcledger10.isChainedZC());
   EXPECT_TRUE(zcledger10.isOptInRBF());
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_FullNode, RegisterAddress_AfterZC)
{
   //create spender lambda
   auto getSpenderPtr = [](const UnspentTxOut& utxo)->shared_ptr<ScriptSpender>
   {
      UTXO entry(utxo.value_, utxo.txHeight_, utxo.txIndex_, utxo.txOutIndex_,
         move(utxo.txHash_), move(utxo.script_));

      auto spender = make_shared<ScriptSpender>(entry);
      spender->setSequence(UINT32_MAX - 2);

      return spender;
   };

   BinaryData ZCHash1, ZCHash2, ZCHash3, ZCHash4;

   //
   TestUtils::setBlocks({ "0", "1", "2", "3" }, blk0dat_);

   theBDMt_->start(DBSettings::initMode());
   auto&& bdvID = DBTestUtils::registerBDV(clients_, BitcoinSettings::getMagicBytes());

   vector<BinaryData> scrAddrVec;
   scrAddrVec.push_back(TestChain::scrAddrA);
   scrAddrVec.push_back(TestChain::scrAddrB);
   scrAddrVec.push_back(TestChain::scrAddrC);
   scrAddrVec.push_back(TestChain::scrAddrD);
   scrAddrVec.push_back(TestChain::scrAddrE);

   //// create assetWlt ////

   //create a root private key
   auto&& wltRoot = CryptoPRNG::generateRandom(32);
   auto assetWlt = AssetWallet_Single::createFromPrivateRoot_Armory135(
      homedir_,
      move(wltRoot), //root as a r value
      {},
      SecureBinaryData(),
      SecureBinaryData(),
      3); //set lookup computation to 3 entries

   //register with db
   vector<BinaryData> addrVec;

   auto hashSet = assetWlt->getAddrHashSet();
   vector<BinaryData> hashVec;
   hashVec.insert(hashVec.begin(), hashSet.begin(), hashSet.end());

   DBTestUtils::registerWallet(clients_, bdvID, hashVec, assetWlt->getID());
   DBTestUtils::registerWallet(clients_, bdvID, scrAddrVec, "wallet1");

   auto bdvPtr = DBTestUtils::getBDV(clients_, bdvID);

   //wait on signals
   DBTestUtils::goOnline(clients_, bdvID);
   DBTestUtils::waitOnBDMReady(clients_, bdvID);
   auto wlt = bdvPtr->getWalletOrLockbox(wallet1id);
   auto dbAssetWlt = bdvPtr->getWalletOrLockbox(assetWlt->getID());

   //check balances
   const ScrAddrObj* scrObj;
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 55 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrD);
   EXPECT_EQ(scrObj->getFullBalance(), 5 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrE);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);

   //check new wallet balances
   for (auto& scripthash : hashSet)
   {
      scrObj = dbAssetWlt->getScrAddrObjByKey(scripthash);
      EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   }

   {
      ////spend 27 from wlt to assetWlt's first 2 unused addresses
      ////send rest back to scrAddrA

      auto spendVal = 27 * COIN;
      Signer signer;
      signer.setLockTime(3);

      //instantiate resolver feed overloaded object
      auto feed = make_shared<ResolverUtils::TestResolverFeed>();
      feed->addPrivKey(TestChain::privKeyAddrB);
      feed->addPrivKey(TestChain::privKeyAddrC);
      feed->addPrivKey(TestChain::privKeyAddrD);
      feed->addPrivKey(TestChain::privKeyAddrE);

      //get utxo list for spend value
      auto&& unspentVec = wlt->getSpendableTxOutListForValue(spendVal);

      vector<UnspentTxOut> utxoVec;
      uint64_t tval = 0;
      auto utxoIter = unspentVec.begin();
      while (utxoIter != unspentVec.end())
      {
         tval += utxoIter->getValue();
         utxoVec.push_back(*utxoIter);

         if (tval > spendVal)
            break;

         ++utxoIter;
      }

      //create script spender objects
      uint64_t total = 0;
      for (auto& utxo : utxoVec)
      {
         total += utxo.getValue();
         signer.addSpender(getSpenderPtr(utxo));
      }

      //spend 12 to first address
      auto addr0 = assetWlt->getNewAddress();
      signer.addRecipient(addr0->getRecipient(12 * COIN));
      addrVec.push_back(addr0->getPrefixedHash());

      //spend 15 to addr 1, use P2PKH
      auto addr1 = assetWlt->getNewAddress();
      signer.addRecipient(addr1->getRecipient(15 * COIN));
      addrVec.push_back(addr1->getPrefixedHash());

      if (total > spendVal)
      {
         //deal with change, no fee
         auto changeVal = total - spendVal;
         auto recipientChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrD.getSliceCopy(1, 20), changeVal);
         signer.addRecipient(recipientChange);
      }

      //sign, verify then broadcast
      signer.setFeed(feed);
      signer.sign();
      EXPECT_TRUE(signer.verify());

      auto rawTx = signer.serializeSignedTx();
      DBTestUtils::ZcVector zcVec;
      zcVec.push_back(rawTx, 14000000);

      ZCHash1 = move(BtcUtils::getHash256(rawTx));
      DBTestUtils::pushNewZc(theBDMt_, zcVec);
      DBTestUtils::waitOnNewZcSignal(clients_, bdvID);
   }

   //check balances
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 55 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrD);
   EXPECT_EQ(scrObj->getFullBalance(), 8 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrE);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);

   auto&& wallet1_balanceCount = 
      DBTestUtils::getBalanceAndCount(clients_, bdvID, "wallet1", 3);

   EXPECT_EQ(wallet1_balanceCount[0], 143 * COIN);
   EXPECT_EQ(wallet1_balanceCount[1], 40 * COIN);
   EXPECT_EQ(wallet1_balanceCount[2], 143 * COIN);

   //check new wallet balances
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[0]);
   EXPECT_EQ(scrObj->getFullBalance(), 12 * COIN);
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[1]);
   EXPECT_EQ(scrObj->getFullBalance(), 15 * COIN);

   auto&& assetWlt_balanceCount =
      DBTestUtils::getBalanceAndCount(clients_, bdvID, assetWlt->getID(), 3);

   EXPECT_EQ(assetWlt_balanceCount[0], 27 * COIN);
   EXPECT_EQ(assetWlt_balanceCount[1], 0 * COIN);
   EXPECT_EQ(assetWlt_balanceCount[2], 27 * COIN);

   //grab ledger
   auto&& zcledger = DBTestUtils::getLedgerEntryFromWallet(dbAssetWlt, ZCHash1);
   EXPECT_EQ(zcledger.getValue(), 27 * COIN);
   //EXPECT_EQ(zcledger.getTxTime(), 14000000);
   EXPECT_TRUE(zcledger.isOptInRBF());

   //register new address
   assetWlt->extendPublicChain(1);
   hashSet = assetWlt->getAddrHashSet();
   hashVec.clear();
   hashVec.insert(hashVec.begin(), hashSet.begin(), hashSet.end());
   DBTestUtils::registerWallet(clients_, bdvID, hashVec, assetWlt->getID());

   //check balances
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 55 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrD);
   EXPECT_EQ(scrObj->getFullBalance(), 8 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrE);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);

   wallet1_balanceCount =
      DBTestUtils::getBalanceAndCount(clients_, bdvID, "wallet1", 3);

   EXPECT_EQ(wallet1_balanceCount[0], 143 * COIN);
   EXPECT_EQ(wallet1_balanceCount[1], 40 * COIN);
   EXPECT_EQ(wallet1_balanceCount[2], 143 * COIN);

   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[0]);
   EXPECT_EQ(scrObj->getFullBalance(), 12 * COIN);
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[1]);
   EXPECT_EQ(scrObj->getFullBalance(), 15 * COIN);

   assetWlt_balanceCount =
      DBTestUtils::getBalanceAndCount(clients_, bdvID, assetWlt->getID(), 3);

   EXPECT_EQ(assetWlt_balanceCount[0], 27 * COIN);
   EXPECT_EQ(assetWlt_balanceCount[1], 0 * COIN);
   EXPECT_EQ(assetWlt_balanceCount[2], 27 * COIN);
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_FullNode, ChainZC_RBFchild_Test)
{
   //create spender lambda
   auto getSpenderPtr = [](
      const UnspentTxOut& utxo, bool flagRBF)
      ->shared_ptr<ScriptSpender>
   {
      UTXO entry(utxo.value_, utxo.txHeight_, utxo.txIndex_, utxo.txOutIndex_,
         move(utxo.txHash_), move(utxo.script_));

      auto spender = make_shared<ScriptSpender>(entry);

      if(flagRBF)
         spender->setSequence(UINT32_MAX - 2);

      return spender;
   };

   BinaryData ZCHash1, ZCHash2, ZCHash3;

   //
   TestUtils::setBlocks({ "0", "1", "2", "3" }, blk0dat_);

   theBDMt_->start(DBSettings::initMode());
   auto&& bdvID = DBTestUtils::registerBDV(clients_, BitcoinSettings::getMagicBytes());

   vector<BinaryData> scrAddrVec;
   scrAddrVec.push_back(TestChain::scrAddrA);
   scrAddrVec.push_back(TestChain::scrAddrB);
   scrAddrVec.push_back(TestChain::scrAddrC);
   scrAddrVec.push_back(TestChain::scrAddrD);
   scrAddrVec.push_back(TestChain::scrAddrE);

   //// create assetWlt ////

   //create a root private key
   auto&& wltRoot = CryptoPRNG::generateRandom(32);
   auto assetWlt = AssetWallet_Single::createFromPrivateRoot_Armory135(
      homedir_,
      move(wltRoot), //root as a r value
      {},
      SecureBinaryData(),
      SecureBinaryData(),      
      10); //set lookup computation to 10 entries

           //register with db
   vector<BinaryData> addrVec;

   auto hashSet = assetWlt->getAddrHashSet();
   vector<BinaryData> hashVec;
   hashVec.insert(hashVec.begin(), hashSet.begin(), hashSet.end());

   DBTestUtils::registerWallet(clients_, bdvID, hashVec, assetWlt->getID());
   DBTestUtils::registerWallet(clients_, bdvID, scrAddrVec, "wallet1");

   auto bdvPtr = DBTestUtils::getBDV(clients_, bdvID);

   //wait on signals
   DBTestUtils::goOnline(clients_, bdvID);
   DBTestUtils::waitOnBDMReady(clients_, bdvID);
   auto wlt = bdvPtr->getWalletOrLockbox(wallet1id);
   auto dbAssetWlt = bdvPtr->getWalletOrLockbox(assetWlt->getID());

   //check balances
   const ScrAddrObj* scrObj;
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 55 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrD);
   EXPECT_EQ(scrObj->getFullBalance(), 5 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrE);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);

   //check new wallet balances
   for (auto& scripthash : hashSet)
   {
      scrObj = dbAssetWlt->getScrAddrObjByKey(scripthash);
      EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   }

   {
      ////spend 27 from wlt to assetWlt's first 2 unused addresses
      ////send rest back to scrAddrA

      auto spendVal = 27 * COIN;
      Signer signer;

      //instantiate resolver feed overloaded object
      auto feed = make_shared<ResolverUtils::TestResolverFeed>();
      feed->addPrivKey(TestChain::privKeyAddrB);
      feed->addPrivKey(TestChain::privKeyAddrC);
      feed->addPrivKey(TestChain::privKeyAddrD);
      feed->addPrivKey(TestChain::privKeyAddrE);

      //get utxo list for spend value
      auto&& unspentVec = wlt->getSpendableTxOutListForValue(spendVal);

      vector<UnspentTxOut> utxoVec;
      uint64_t tval = 0;
      auto utxoIter = unspentVec.begin();
      while (utxoIter != unspentVec.end())
      {
         tval += utxoIter->getValue();
         utxoVec.push_back(*utxoIter);

         if (tval > spendVal)
            break;

         ++utxoIter;
      }

      //create script spender objects
      uint64_t total = 0;
      for (auto& utxo : utxoVec)
      {
         total += utxo.getValue();
         signer.addSpender(getSpenderPtr(utxo, true));
      }

      //spend 12 to first address
      auto addr0 = assetWlt->getNewAddress();
      signer.addRecipient(addr0->getRecipient(12 * COIN));
      addrVec.push_back(addr0->getPrefixedHash());

      //spend 15 to addr 1, use P2PKH
      auto addr1 = assetWlt->getNewAddress();
      signer.addRecipient(addr1->getRecipient(15 * COIN));
      addrVec.push_back(addr1->getPrefixedHash());

      if (total > spendVal)
      {
         //deal with change, no fee
         auto changeVal = total - spendVal;
         auto recipientChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrD.getSliceCopy(1, 20), changeVal);
         signer.addRecipient(recipientChange);
      }

      //sign, verify then broadcast
      signer.setFeed(feed);
      signer.sign();
      EXPECT_TRUE(signer.verify());

      auto rawTx = signer.serializeSignedTx();
      DBTestUtils::ZcVector zcVec;
      zcVec.push_back(rawTx, 14000000);

      ZCHash1 = move(BtcUtils::getHash256(rawTx));
      DBTestUtils::pushNewZc(theBDMt_, zcVec);
      auto&& ledgerVec = DBTestUtils::waitOnNewZcSignal(clients_, bdvID);
      EXPECT_EQ(ledgerVec.first.size(), 2);
      EXPECT_EQ(ledgerVec.second.size(), 0);

      for (auto& ledger : ledgerVec.first)
         EXPECT_EQ(ledger.getTxHash(), ZCHash1);
   }

   //check balances
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 55 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrD);
   EXPECT_EQ(scrObj->getFullBalance(), 8 * COIN);

   {
      scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrE);
      auto&& zcledger_sa = DBTestUtils::getLedgerEntryFromAddr(
         (ScrAddrObj*)scrObj, ZCHash1);
      EXPECT_EQ(zcledger_sa.getValue(), -30 * COIN);
      //EXPECT_EQ(zcledger_sa.getTxTime(), 14000000);
      EXPECT_TRUE(zcledger_sa.isOptInRBF());
      EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   }

   //check new wallet balances
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[0]);
   EXPECT_EQ(scrObj->getFullBalance(), 12 * COIN);
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[1]);
   EXPECT_EQ(scrObj->getFullBalance(), 15 * COIN);

   //grab ledger
   auto&& zcledger = DBTestUtils::getLedgerEntryFromWallet(dbAssetWlt, ZCHash1);
   EXPECT_EQ(zcledger.getValue(), 27 * COIN);
   //EXPECT_EQ(zcledger.getTxTime(), 14000000);
   EXPECT_TRUE(zcledger.isOptInRBF());

   //cpfp the first zc
   {
      Signer signer3;

      //instantiate resolver feed overloaded object
      auto assetFeed = make_shared<ResolverFeed_AssetWalletSingle>(assetWlt);

      //get utxo list for spend value
      auto&& unspentVec = dbAssetWlt->getSpendableTxOutListZC();

      //create script spender objects
      uint64_t total = 0;
      for (auto& utxo : unspentVec)
      {
         total += utxo.getValue();
         signer3.addSpender(getSpenderPtr(utxo, true));
      }

      //spend 4 to new address
      auto addr0 = assetWlt->getNewAddress();
      signer3.addRecipient(addr0->getRecipient(4 * COIN));
      addrVec.push_back(addr0->getPrefixedHash());

      //spend 6 to new address
      auto addr1 = assetWlt->getNewAddress();
      signer3.addRecipient(addr1->getRecipient(6 * COIN));
      addrVec.push_back(addr1->getPrefixedHash());

      //deal with change, no fee
      auto changeVal = total - 10 * COIN;
      auto recipientChange = make_shared<Recipient_P2PKH>(
         TestChain::scrAddrD.getSliceCopy(1, 20), changeVal);
      signer3.addRecipient(recipientChange);

      //sign, verify then broadcast
      {
         auto lock = assetWlt->lockDecryptedContainer();
         signer3.setFeed(assetFeed);
         signer3.sign();
      }

      auto rawTx = signer3.serializeSignedTx();
      DBTestUtils::ZcVector zcVec3;
      zcVec3.push_back(rawTx, 15000000);

      ZCHash2 = move(BtcUtils::getHash256(rawTx));
      DBTestUtils::pushNewZc(theBDMt_, zcVec3);
      auto&& ledgerVec = DBTestUtils::waitOnNewZcSignal(clients_, bdvID);
      EXPECT_EQ(ledgerVec.first.size(), 2);
      EXPECT_EQ(ledgerVec.second.size(), 0);

      for (auto& ledger : ledgerVec.first)
         EXPECT_EQ(ledger.getTxHash(), ZCHash2);
   }

   //check balances
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 55 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrD);
   EXPECT_EQ(scrObj->getFullBalance(), 25 * COIN);
   {
      scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrE);
      auto&& zcledger_sa = DBTestUtils::getLedgerEntryFromAddr(
         (ScrAddrObj*)scrObj, ZCHash1);
      EXPECT_EQ(zcledger_sa.getValue(), -30 * COIN);
      //EXPECT_EQ(zcledger_sa.getTxTime(), 14000000);
      EXPECT_TRUE(zcledger_sa.isOptInRBF());
      EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   }

   //check new wallet balances
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[0]);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[1]);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);

   {
      scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[2]);
      auto&& zcledger_sa = DBTestUtils::getLedgerEntryFromAddr(
         (ScrAddrObj*)scrObj, ZCHash2);
      EXPECT_EQ(zcledger_sa.getValue(), 4 * COIN);
      //EXPECT_EQ(zcledger_sa.getTxTime(), 15000000);
      EXPECT_TRUE(zcledger_sa.isOptInRBF());
      EXPECT_EQ(scrObj->getFullBalance(), 4 * COIN);
   }

   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[3]);
   EXPECT_EQ(scrObj->getFullBalance(), 6 * COIN);


   //first zc should still be valid
   auto&& zcledger1 = DBTestUtils::getLedgerEntryFromWallet(dbAssetWlt, ZCHash1);
   EXPECT_EQ(zcledger1.getValue(), 27 * COIN);
   //EXPECT_EQ(zcledger1.getTxTime(), 14000000);
   EXPECT_TRUE(zcledger1.isOptInRBF());

   //second zc should be valid
   auto&& zcledger2 = DBTestUtils::getLedgerEntryFromWallet(dbAssetWlt, ZCHash2);
   EXPECT_EQ(zcledger2.getValue(), -17 * COIN);
   //EXPECT_EQ(zcledger2.getTxTime(), 15000000);
   EXPECT_TRUE(zcledger2.isOptInRBF());

   //rbf the child
   {
      auto spendVal = 10 * COIN;
      Signer signer2;

      //instantiate resolver feed
      auto assetFeed = 
         make_shared<ResolverFeed_AssetWalletSingle>(assetWlt);

      //get utxo list for spend value
      auto&& unspentVec = dbAssetWlt->getRBFTxOutList();

      vector<UnspentTxOut> utxoVec;
      uint64_t tval = 0;
      auto utxoIter = unspentVec.begin();
      while (utxoIter != unspentVec.end())
      {
         tval += utxoIter->getValue();
         utxoVec.push_back(*utxoIter);

         if (tval > spendVal)
            break;

         ++utxoIter;
      }

      //create script spender objects
      uint64_t total = 0;
      for (auto& utxo : utxoVec)
      {
         total += utxo.getValue();
         signer2.addSpender(getSpenderPtr(utxo, true));
      }

      //spend 5 to new address
      auto addr0 = assetWlt->getNewAddress();
      signer2.addRecipient(addr0->getRecipient(6 * COIN));
      addrVec.push_back(addr0->getPrefixedHash());


      if (total > spendVal)
      {
         //change addrE, 1 btc fee
         auto changeVal = 5 * COIN;
         auto recipientChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrE.getSliceCopy(1, 20), changeVal);
         signer2.addRecipient(recipientChange);
      }

      //sign, verify then broadcast
      {
         auto lock = assetWlt->lockDecryptedContainer();
         signer2.setFeed(assetFeed);
         signer2.sign();
      }
      EXPECT_TRUE(signer2.verify());

      auto rawTx = signer2.serializeSignedTx();
      DBTestUtils::ZcVector zcVec2;
      zcVec2.push_back(rawTx, 17000000);

      ZCHash3 = move(BtcUtils::getHash256(rawTx));
      DBTestUtils::pushNewZc(theBDMt_, zcVec2);
      auto&& ledgerVec = DBTestUtils::waitOnNewZcSignal(clients_, bdvID);
      EXPECT_EQ(ledgerVec.first.size(), 2);
      EXPECT_EQ(ledgerVec.second.size(), 1);


      for (auto& ledger : ledgerVec.first)
         EXPECT_EQ(ledger.getTxHash(), ZCHash3);

      EXPECT_EQ(*ledgerVec.second.begin(), ZCHash2);
   }

   //check balances
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 55 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrD);
   EXPECT_EQ(scrObj->getFullBalance(), 8 * COIN);
   {
      scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrE);
      auto&& zcledger_sa = DBTestUtils::getLedgerEntryFromAddr(
         (ScrAddrObj*)scrObj, ZCHash1);
      EXPECT_EQ(zcledger_sa.getValue(), -30 * COIN);
      //EXPECT_EQ(zcledger_sa.getTxTime(), 14000000);
      EXPECT_TRUE(zcledger_sa.isOptInRBF());
      EXPECT_EQ(scrObj->getFullBalance(), 5 * COIN);
   }

   //check new wallet balances
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[0]);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[1]);
   EXPECT_EQ(scrObj->getFullBalance(), 15 * COIN);
   {
      scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[2]);
      auto&& zcledger_sa = DBTestUtils::getLedgerEntryFromAddr(
         (ScrAddrObj*)scrObj, ZCHash2);
      EXPECT_EQ(zcledger_sa.getTxHash(), BtcUtils::EmptyHash());
      EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   }
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[3]);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[4]);
   EXPECT_EQ(scrObj->getFullBalance(), 6 * COIN);

   //grab ledgers

   //first zc should be valid
   auto&& zcledger3 = DBTestUtils::getLedgerEntryFromWallet(dbAssetWlt, ZCHash1);
   EXPECT_EQ(zcledger3.getValue(), 27 * COIN);
   //EXPECT_EQ(zcledger3.getTxTime(), 14000000);
   EXPECT_TRUE(zcledger3.isOptInRBF());

   //second zc should be replaced
   auto&& zcledger8 = DBTestUtils::getLedgerEntryFromWallet(dbAssetWlt, ZCHash2);
   EXPECT_EQ(zcledger8.getTxHash(), BtcUtils::EmptyHash_);

   //third zc should be valid
   auto&& zcledger9 = DBTestUtils::getLedgerEntryFromWallet(dbAssetWlt, ZCHash3);
   EXPECT_EQ(zcledger9.getValue(), -6 * COIN);
   //EXPECT_EQ(zcledger9.getTxTime(), 17000000);
   EXPECT_TRUE(zcledger9.isOptInRBF());
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_FullNode, ZC_InOut_SameBlock)
{
   BinaryData ZCHash1, ZCHash2, ZCHash3;

   //
   TestUtils::setBlocks({ "0", "1" }, blk0dat_);

   theBDMt_->start(DBSettings::initMode());
   auto&& bdvID = DBTestUtils::registerBDV(clients_, BitcoinSettings::getMagicBytes());

   vector<BinaryData> scrAddrVec;
   scrAddrVec.push_back(TestChain::scrAddrA);
   scrAddrVec.push_back(TestChain::scrAddrB);
   scrAddrVec.push_back(TestChain::scrAddrC);

   DBTestUtils::registerWallet(clients_, bdvID, scrAddrVec, "wallet1");

   auto bdvPtr = DBTestUtils::getBDV(clients_, bdvID);

   //wait on signals
   DBTestUtils::goOnline(clients_, bdvID);
   DBTestUtils::waitOnBDMReady(clients_, bdvID);
   auto wlt = bdvPtr->getWalletOrLockbox(wallet1id);

   //check balances
   const ScrAddrObj* scrObj;
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);

   //add the 2 zc
   auto&& ZC1 = TestUtils::getTx(2, 1); //block 2, tx 1
   auto&& ZChash1 = BtcUtils::getHash256(ZC1);

   auto&& ZC2 = TestUtils::getTx(2, 2); //block 2, tx 2
   auto&& ZChash2 = BtcUtils::getHash256(ZC2);

   DBTestUtils::ZcVector rawZcVec;
   rawZcVec.push_back(ZC1, 1300000000);
   rawZcVec.push_back(ZC2, 1310000000);

   DBTestUtils::pushNewZc(theBDMt_, rawZcVec);
   DBTestUtils::waitOnNewZcSignal(clients_, bdvID);

   //check balances
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 5 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);

   //add last block
   TestUtils::appendBlocks({ "2" }, blk0dat_);
   DBTestUtils::triggerNewBlockNotification(theBDMt_);
   DBTestUtils::waitOnNewBlockSignal(clients_, bdvID);

   //check balances
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 55 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_FullNode, TwoZC_CheckLedgers)
{
   //create spender lambda
   auto getSpenderPtr = [](
      const UnspentTxOut& utxo)
      ->shared_ptr<ScriptSpender>
   {
      UTXO entry(utxo.value_, utxo.txHeight_, utxo.txIndex_, utxo.txOutIndex_,
         move(utxo.txHash_), move(utxo.script_));

      auto spender = make_shared<ScriptSpender>(entry);
      spender->setSequence(UINT32_MAX - 2);

      return spender;
   };

   BinaryData ZCHash1, ZCHash2, ZCHash3, ZCHash4;

   //
   TestUtils::setBlocks({ "0", "1", "2", "3" }, blk0dat_);

   theBDMt_->start(DBSettings::initMode());
   auto&& bdvID = DBTestUtils::registerBDV(clients_, BitcoinSettings::getMagicBytes());

   vector<BinaryData> scrAddrVec;
   scrAddrVec.push_back(TestChain::scrAddrA);
   scrAddrVec.push_back(TestChain::scrAddrB);
   scrAddrVec.push_back(TestChain::scrAddrC);
   scrAddrVec.push_back(TestChain::scrAddrE);

   //// create assetWlt ////

   //create a root private key
   auto&& wltRoot = CryptoPRNG::generateRandom(32);
   auto assetWlt = AssetWallet_Single::createFromPrivateRoot_Armory135(
      homedir_,
      move(wltRoot),
      {},
      SecureBinaryData(), //empty passphrase
      SecureBinaryData(),
      5);

   //register with db
   vector<BinaryData> addrVec;

   auto hashSet = assetWlt->getAddrHashSet();
   vector<BinaryData> hashVec;
   hashVec.insert(hashVec.begin(), hashSet.begin(), hashSet.end());

   //add existing address to asset wlt for zc test purposes
   hashVec.push_back(TestChain::scrAddrD);

   DBTestUtils::registerWallet(clients_, bdvID, hashVec, assetWlt->getID());
   DBTestUtils::registerWallet(clients_, bdvID, scrAddrVec, "wallet1");

   auto bdvPtr = DBTestUtils::getBDV(clients_, bdvID);

   //wait on signals
   DBTestUtils::goOnline(clients_, bdvID);
   DBTestUtils::waitOnBDMReady(clients_, bdvID);
   EXPECT_EQ(DBTestUtils::getTopBlockHeight(iface_, HEADERS), 3);

   auto wlt = bdvPtr->getWalletOrLockbox(wallet1id);
   auto dbAssetWlt = bdvPtr->getWalletOrLockbox(assetWlt->getID());
   auto delegateID = DBTestUtils::getLedgerDelegate(clients_, bdvID);

   //check balances
   const ScrAddrObj* scrObj;
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 55 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrE);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);

   //check new wallet balances
   for (auto& scripthash : hashSet)
   {
      scrObj = dbAssetWlt->getScrAddrObjByKey(scripthash);
      EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   }

   {
      /*
      Create a tx to fund assetWlt from scrAddrF. This will appear as
      an external tx since scrAddrF isn't registered
      */
      Signer signer;

      //instantiate resolver feed overloaded object
      auto feed = make_shared<ResolverUtils::TestResolverFeed>();
      feed->addPrivKey(TestChain::privKeyAddrF);

      //create spender
      {
         auto spender = make_shared<ScriptSpender>(firstUtxoScrAddrF_);
         signer.addSpender(spender);
      }

      auto assetWlt_addr = assetWlt->getNewAddress(
         AddressEntryType(AddressEntryType_P2WPKH | AddressEntryType_P2SH));
      addrVec.push_back(assetWlt_addr->getPrefixedHash());
      signer.addRecipient(assetWlt_addr->getRecipient(firstUtxoScrAddrF_.value_));

      //sign, verify then broadcast
      signer.setFeed(feed);
      signer.sign();
      EXPECT_TRUE(signer.verify());

      auto rawTx = signer.serializeSignedTx();
      DBTestUtils::ZcVector zcVec;
      zcVec.push_back(rawTx, 14000000);

      ZCHash1 = move(BtcUtils::getHash256(rawTx));
      DBTestUtils::pushNewZc(theBDMt_, zcVec);
      auto&& ledgerVec = DBTestUtils::waitOnNewZcSignal(clients_, bdvID);
      EXPECT_EQ(ledgerVec.first.size(), 1);
      EXPECT_EQ(ledgerVec.second.size(), 0);

      for (auto& ledger : ledgerVec.first)
         EXPECT_EQ(ledger.getTxHash(), ZCHash1);
   }

   //check balances
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 55 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrE);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);

   //check new wallet balances
   {
      scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[0]);
      auto&& zcledgerSA = DBTestUtils::getLedgerEntryFromAddr(
         (ScrAddrObj*)scrObj, ZCHash1);
      EXPECT_EQ(zcledgerSA.getValue(), 5 * COIN);
      //EXPECT_EQ(zcledgerSA.getTxTime(), 14000000);
      EXPECT_FALSE(zcledgerSA.isOptInRBF());
      EXPECT_EQ(scrObj->getFullBalance(), 5 * COIN);
   }
   scrObj = dbAssetWlt->getScrAddrObjByKey(TestChain::scrAddrD);
   EXPECT_EQ(scrObj->getFullBalance(), 5 * COIN);

   //grab wallet ledger
   auto&& zcledger = DBTestUtils::getLedgerEntryFromWallet(dbAssetWlt, ZCHash1);
   EXPECT_EQ(zcledger.getValue(), 5 * COIN);
   //EXPECT_EQ(zcledger.getTxTime(), 14000000);
   EXPECT_FALSE(zcledger.isOptInRBF());
   EXPECT_FALSE(zcledger.isSentToSelf());

   //grab delegate ledger
   auto&& delegateLedger = DBTestUtils::getHistoryPage(clients_, bdvID, delegateID, 0);

   unsigned zc1_count = 0;
   for (auto& ld : delegateLedger)
   {
      if (ld.getTxHash() == ZCHash1)
         zc1_count++;
   }

   EXPECT_EQ(zc1_count, 1);

   {
      ////assetWlt send-to-self
      auto spendVal = 5 * COIN;
      Signer signer2;

      auto feed = make_shared<ResolverUtils::HybridFeed>(assetWlt);
      auto addToFeed = [feed](const BinaryData& key)->void
      {
         feed->testFeed_.addPrivKey(key);
      };

      addToFeed(TestChain::privKeyAddrD);


      //get utxo list for spend value
      auto&& unspentVec = dbAssetWlt->getSpendableTxOutListForValue();

      vector<UnspentTxOut> utxoVec;
      uint64_t tval = 0;
      auto utxoIter = unspentVec.begin();
      while (utxoIter != unspentVec.end())
      {
         tval += utxoIter->getValue();
         utxoVec.push_back(*utxoIter);

         if (tval >= spendVal)
            break;

         ++utxoIter;
      }

      //create script spender objects
      uint64_t total = 0;
      for (auto& utxo : utxoVec)
      {
         total += utxo.getValue();
         signer2.addSpender(getSpenderPtr(utxo));
      }

      auto addr2 = assetWlt->getNewAddress(
         AddressEntryType(AddressEntryType_P2WPKH | AddressEntryType_P2SH));
      signer2.addRecipient(addr2->getRecipient(spendVal));
      addrVec.push_back(addr2->getPrefixedHash());

      //sign, verify then broadcast
      signer2.setFeed(feed);
      signer2.sign();
      EXPECT_TRUE(signer2.verify());

      auto rawTx = signer2.serializeSignedTx();
      DBTestUtils::ZcVector zcVec2;
      zcVec2.push_back(rawTx, 15000000);

      ZCHash2 = move(BtcUtils::getHash256(rawTx));
      DBTestUtils::pushNewZc(theBDMt_, zcVec2);
      auto&& ledgerVec = DBTestUtils::waitOnNewZcSignal(clients_, bdvID);
      for (auto& ledger : ledgerVec.first)
         EXPECT_EQ(ledger.getTxHash(), ZCHash2);
   }

   //check balances
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 55 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrE);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);

   //check new wallet balances
   {
      scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[0]);
      auto&& zcledgerSA = DBTestUtils::getLedgerEntryFromAddr(
         (ScrAddrObj*)scrObj, ZCHash1);
      EXPECT_EQ(zcledgerSA.getValue(), 5 * COIN);
      //EXPECT_EQ(zcledgerSA.getTxTime(), 14000000);
      EXPECT_FALSE(zcledgerSA.isOptInRBF());
      EXPECT_EQ(scrObj->getFullBalance(), 5 * COIN);
   }

   scrObj = dbAssetWlt->getScrAddrObjByKey(TestChain::scrAddrD);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);

   //grab wallet ledger
   auto&& zcledger2 = DBTestUtils::getLedgerEntryFromWallet(dbAssetWlt, ZCHash1);
   EXPECT_EQ(zcledger2.getValue(), 5 * COIN);
   EXPECT_EQ(zcledger2.getBlockNum(), UINT32_MAX);
   EXPECT_FALSE(zcledger2.isSentToSelf());

   auto&& zcledger3 = DBTestUtils::getLedgerEntryFromWallet(dbAssetWlt, ZCHash2);
   EXPECT_EQ(zcledger3.getValue(), 5 * COIN);
   EXPECT_EQ(zcledger3.getBlockNum(), UINT32_MAX);
   EXPECT_TRUE(zcledger3.isSentToSelf());

   //grab delegate ledger
   auto&& delegateLedger2 = DBTestUtils::getHistoryPage(clients_, bdvID, delegateID, 0);

   unsigned zc2_count = 0;
   unsigned zc3_count = 0;

   for (auto& ld : delegateLedger2)
   {
      if (ld.getTxHash() == ZCHash1)
         zc2_count++;

      if (ld.getTxHash() == ZCHash2)
         zc3_count++;
   }

   EXPECT_EQ(zc2_count, 1);
   EXPECT_EQ(zc3_count, 1);

   //mine a new block
   DBTestUtils::mineNewBlock(theBDMt_, TestChain::addrB, 1);
   DBTestUtils::waitOnNewBlockSignal(clients_, bdvID);

   //check chain is 1 block longer
   EXPECT_EQ(DBTestUtils::getTopBlockHeight(iface_, HEADERS), 4);

   //check balances
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 80 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 55 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrE);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);

   //check new wallet balances
   {
      scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[0]);
      auto&& zcledgerSA = DBTestUtils::getLedgerEntryFromAddr(
         (ScrAddrObj*)scrObj, ZCHash1);
      EXPECT_EQ(zcledgerSA.getValue(), 5 * COIN);
      //EXPECT_EQ(zcledgerSA.getTxTime(), 14000000);
      EXPECT_FALSE(zcledgerSA.isOptInRBF());
      EXPECT_EQ(scrObj->getFullBalance(), 5 * COIN);
   }

   scrObj = dbAssetWlt->getScrAddrObjByKey(TestChain::scrAddrD);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);

   //grab wallet ledger
   zcledger2 = DBTestUtils::getLedgerEntryFromWallet(dbAssetWlt, ZCHash1);
   EXPECT_EQ(zcledger2.getValue(), 5 * COIN);
   EXPECT_EQ(zcledger2.getBlockNum(), 4);
   EXPECT_FALSE(zcledger2.isSentToSelf());

   zcledger3 = DBTestUtils::getLedgerEntryFromWallet(dbAssetWlt, ZCHash2);
   EXPECT_EQ(zcledger3.getValue(), 5 * COIN);
   EXPECT_EQ(zcledger3.getBlockNum(), 4);
   EXPECT_TRUE(zcledger3.isSentToSelf());

   //grab delegate ledger
   delegateLedger2 = DBTestUtils::getHistoryPage(clients_, bdvID, delegateID, 0);

   zc2_count = 0;
   zc3_count = 0;

   for (auto& ld : delegateLedger2)
   {
      if (ld.getTxHash() == ZCHash1)
         zc2_count++;

      if (ld.getTxHash() == ZCHash2)
         zc3_count++;
   }

   EXPECT_EQ(zc2_count, 1);
   EXPECT_EQ(zc3_count, 1);
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
class ZeroConfTests_Supernode : public ::testing::Test
{
protected:
   BlockDataManagerThread *theBDMt_;
   Clients* clients_;

   void initBDM(void)
   {
      DBTestUtils::init();

      ArmoryConfig::reset();
      DBSettings::setServiceType(SERVICE_UNITTEST);
      ArmoryConfig::parseArgs({
         "--datadir=./fakehomedir",
         "--dbdir=./ldbtestdir",
         "--satoshi-datadir=./blkfiletest",
         "--db-type=DB_SUPER",
         "--thread-count=3",
      });

      theBDMt_ = new BlockDataManagerThread();
      iface_ = theBDMt_->bdm()->getIFace();

      auto nodePtr = dynamic_pointer_cast<NodeUnitTest>(
         NetworkSettings::bitcoinNodes().first);

      nodePtr->setBlockchain(theBDMt_->bdm()->blockchain());
      nodePtr->setBlockFiles(theBDMt_->bdm()->blockFiles());
      nodePtr->setIface(iface_);

      auto mockedShutdown = [](void)->void {};
      clients_ = new Clients(theBDMt_, mockedShutdown);
   }

   /////////////////////////////////////////////////////////////////////////////
   virtual void SetUp()
   {
      LOGDISABLESTDOUT();
      zeros_ = READHEX("00000000");

      blkdir_ = string("./blkfiletest");
      homedir_ = string("./fakehomedir");
      ldbdir_ = string("./ldbtestdir");

      DBUtils::removeDirectory(blkdir_);
      DBUtils::removeDirectory(homedir_);
      DBUtils::removeDirectory(ldbdir_);

      mkdir(blkdir_ + "/blocks");
      mkdir(homedir_);
      mkdir(ldbdir_);

      // Put the first 5 blocks into the blkdir
      blk0dat_ = BtcUtils::getBlkFilename(blkdir_ + "/blocks", 0);
      TestUtils::setBlocks({ "0", "1", "2", "3", "4", "5" }, blk0dat_);

      initBDM();

      wallet1id = "wallet1";
   }

   /////////////////////////////////////////////////////////////////////////////
   virtual void TearDown(void)
   {
      if (clients_ != nullptr)
      {
         clients_->exitRequestLoop();
         clients_->shutdown();
      }

      delete clients_;
      delete theBDMt_;

      theBDMt_ = nullptr;
      clients_ = nullptr;

      DBUtils::removeDirectory(blkdir_);
      DBUtils::removeDirectory(homedir_);
      DBUtils::removeDirectory("./ldbtestdir");

      mkdir("./ldbtestdir");

      ArmoryConfig::reset();

      LOGENABLESTDOUT();
      CLEANUP_ALL_TIMERS();
   }

   LMDBBlockDatabase* iface_;
   BinaryData zeros_;

   string blkdir_;
   string homedir_;
   string ldbdir_;
   string blk0dat_;

   string wallet1id;
};

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_Supernode, ZeroConfUpdate)
{
   //create script spender objects
   auto getSpenderPtr = [](
      const UnspentTxOut& utxo)
      ->shared_ptr<ScriptSpender>
   {
      UTXO entry(utxo.value_, utxo.txHeight_, utxo.txIndex_, utxo.txOutIndex_,
         move(utxo.txHash_), move(utxo.script_));

      auto spender = make_shared<ScriptSpender>(entry);
      spender->setSequence(UINT32_MAX - 2);

      return spender;
   };

   TestUtils::setBlocks({ "0", "1", "2", "3" }, blk0dat_);

   vector<BinaryData> scrAddrVec;
   scrAddrVec.push_back(TestChain::scrAddrA);
   scrAddrVec.push_back(TestChain::scrAddrB);
   scrAddrVec.push_back(TestChain::scrAddrC);
   scrAddrVec.push_back(TestChain::scrAddrE);

   theBDMt_->start(DBSettings::initMode());
   auto&& bdvID = DBTestUtils::registerBDV(clients_, BitcoinSettings::getMagicBytes());

   DBTestUtils::registerWallet(clients_, bdvID, scrAddrVec, "wallet1");

   auto bdvPtr = DBTestUtils::getBDV(clients_, bdvID);

   //wait on signals
   DBTestUtils::goOnline(clients_, bdvID);
   DBTestUtils::waitOnBDMReady(clients_, bdvID);
   auto wlt = bdvPtr->getWalletOrLockbox(wallet1id);

   BinaryData ZChash;

   {
      ////spend 27 from wlt to assetWlt's first 2 unused addresses
      ////send rest back to scrAddrA

      auto spendVal = 27 * COIN;
      Signer signer;
      signer.setLockTime(3);

      //instantiate resolver feed overloaded object
      auto feed = make_shared<ResolverUtils::TestResolverFeed>();
      feed->addPrivKey(TestChain::privKeyAddrB);
      feed->addPrivKey(TestChain::privKeyAddrC);
      feed->addPrivKey(TestChain::privKeyAddrD);
      feed->addPrivKey(TestChain::privKeyAddrE);

      //get utxo list for spend value
      auto&& unspentVec = wlt->getSpendableTxOutListForValue(spendVal);

      vector<UnspentTxOut> utxoVec;
      uint64_t tval = 0;
      auto utxoIter = unspentVec.begin();
      while (utxoIter != unspentVec.end())
      {
         tval += utxoIter->getValue();
         utxoVec.push_back(*utxoIter);

         if (tval > spendVal)
            break;

         ++utxoIter;
      }

      //create script spender objects
      uint64_t total = 0;
      for (auto& utxo : utxoVec)
      {
         total += utxo.getValue();
         signer.addSpender(getSpenderPtr(utxo));
      }

      //spendVal to addrE
      auto recipientChange = make_shared<Recipient_P2PKH>(
         TestChain::scrAddrD.getSliceCopy(1, 20), spendVal);
      signer.addRecipient(recipientChange);

      if (total > spendVal)
      {
         //change to scrAddrD, no fee
         auto changeVal = total - spendVal;
         auto recipientChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrE.getSliceCopy(1, 20), changeVal);
         signer.addRecipient(recipientChange);
      }

      //sign, verify then broadcast
      signer.setFeed(feed);
      signer.sign();
      EXPECT_TRUE(signer.verify());

      Tx zctx(signer.serializeSignedTx());
      ZChash = zctx.getThisHash();

      DBTestUtils::ZcVector zcVec;
      zcVec.push_back(signer.serializeSignedTx(), 1300000000);

      DBTestUtils::pushNewZc(theBDMt_, zcVec);
      DBTestUtils::waitOnNewZcSignal(clients_, bdvID);
   }

   EXPECT_EQ(wlt->getScrAddrObjByKey(TestChain::scrAddrA)->getFullBalance(), 50 * COIN);
   EXPECT_EQ(wlt->getScrAddrObjByKey(TestChain::scrAddrB)->getFullBalance(), 30 * COIN);
   EXPECT_EQ(wlt->getScrAddrObjByKey(TestChain::scrAddrC)->getFullBalance(), 55 * COIN);
   EXPECT_EQ(wlt->getScrAddrObjByKey(TestChain::scrAddrE)->getFullBalance(), 3 * COIN);

   //test ledger entry
   LedgerEntry le = DBTestUtils::getLedgerEntryFromWallet(wlt, ZChash);

   //EXPECT_EQ(le.getTxTime(), 1300000000);
   EXPECT_EQ(le.isSentToSelf(), false);
   EXPECT_EQ(le.getValue(), -27 * COIN);

   //check ZChash in DB
   {
      BinaryData zcKey = WRITE_UINT16_BE(0xFFFF);
      zcKey.append(WRITE_UINT32_LE(0));
      auto ss = theBDMt_->bdm()->zeroConfCont()->getSnapshot();
      EXPECT_EQ(ss->getHashForKey(zcKey), ZChash);
   }

   //grab ZC by hash
   auto&& txobj = DBTestUtils::getTxByHash(clients_, bdvID, ZChash);
   EXPECT_EQ(txobj.getThisHash(), ZChash);
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_Supernode, UnrelatedZC_CheckLedgers)
{
   TestUtils::setBlocks({ "0", "1", "2", "3", "4" }, blk0dat_);

   theBDMt_->start(DBSettings::initMode());
   auto&& bdvID = DBTestUtils::registerBDV(clients_, BitcoinSettings::getMagicBytes());

   vector<BinaryData> scrAddrVec;
   scrAddrVec.push_back(TestChain::scrAddrA);
   scrAddrVec.push_back(TestChain::scrAddrB);
   scrAddrVec.push_back(TestChain::scrAddrC);
   DBTestUtils::registerWallet(clients_, bdvID, scrAddrVec, "wallet1");

   auto bdvPtr = DBTestUtils::getBDV(clients_, bdvID);

   //wait on signals
   DBTestUtils::goOnline(clients_, bdvID);
   DBTestUtils::waitOnBDMReady(clients_, bdvID);
   auto wlt = bdvPtr->getWalletOrLockbox(wallet1id);
   auto delegateID = DBTestUtils::getLedgerDelegate(clients_, bdvID);

   //check balances
   const ScrAddrObj* scrObj;
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 10 * COIN);

   StoredScriptHistory ssh;
   iface_->getStoredScriptHistory(ssh, TestChain::scrAddrD);
   EXPECT_EQ(ssh.getScriptBalance(), 60 * COIN);
   iface_->getStoredScriptHistory(ssh, TestChain::scrAddrF);
   EXPECT_EQ(ssh.getScriptBalance(), 10 * COIN);

   //Create zc that spends from addr D to F. This is supernode so the DB
   //should track this ZC even though it isn't registered. Send the ZC as
   //a batch along with a ZC that hits our wallets, in order to get the 
   //notification, which comes at the BDV level (i.e. only for registered
   //wallets).
   
   auto&& ZC1 = TestUtils::getTx(5, 2); //block 5, tx 2
   auto&& ZChash1 = BtcUtils::getHash256(ZC1);

   auto&& ZC2 = TestUtils::getTx(5, 1); //block 5, tx 1
   auto&& ZChash2 = BtcUtils::getHash256(ZC2);

   DBTestUtils::ZcVector zcVec1;
   zcVec1.push_back(ZC1, 14000000);
   zcVec1.push_back(ZC2, 14100000);

   DBTestUtils::pushNewZc(theBDMt_, zcVec1);
   DBTestUtils::waitOnNewZcSignal(clients_, bdvID);

   //check balances
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 20 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 20 * COIN);

   try
   {
      auto snapshot = theBDMt_->bdm()->zeroConfCont()->getSnapshot();
      auto zcTxios = snapshot->getTxioMapForScrAddr(TestChain::scrAddrD);
      EXPECT_EQ(zcTxios.size(), 1);
      iface_->getStoredScriptHistory(ssh, TestChain::scrAddrD);
      DBTestUtils::addTxioToSsh(ssh, zcTxios);
      EXPECT_EQ(ssh.getScriptBalance(), 65 * COIN);
   }
   catch (exception&)
   {
      ASSERT_TRUE(false);
   }

   {
      auto snapshot = theBDMt_->bdm()->zeroConfCont()->getSnapshot();
      auto zcTxios = snapshot->getTxioMapForScrAddr(TestChain::scrAddrF);
      ASSERT_FALSE(zcTxios.empty());
      iface_->getStoredScriptHistory(ssh, TestChain::scrAddrF);
      DBTestUtils::addTxioToSsh(ssh, zcTxios);
      EXPECT_EQ(ssh.getScriptBalance(), 5 * COIN);
   }

   //grab ledger for 1st ZC, should be empty
   auto zcledger = DBTestUtils::getLedgerEntryFromWallet(wlt, ZChash1);
   EXPECT_EQ(zcledger.getTxHash(), BtcUtils::EmptyHash());

   //grab ledger for 2nd ZC
   zcledger = DBTestUtils::getLedgerEntryFromWallet(wlt, ZChash2);
   EXPECT_EQ(zcledger.getValue(), 30 * COIN);
   EXPECT_EQ(zcledger.getBlockNum(), UINT32_MAX);
   EXPECT_FALSE(zcledger.isOptInRBF());

   //grab delegate ledger
   auto&& delegateLedger = 
      DBTestUtils::getHistoryPage(clients_, bdvID, delegateID, 0);

   unsigned zc2_count = 0;
   for (auto& ld : delegateLedger)
   {
      if (ld.getTxHash() == ZChash2)
         zc2_count++;
   }

   EXPECT_EQ(zc2_count, 1);

   //push last block
   TestUtils::setBlocks({ "0", "1", "2", "3", "4", "5" }, blk0dat_);
   DBTestUtils::triggerNewBlockNotification(theBDMt_);
   DBTestUtils::waitOnNewBlockSignal(clients_, bdvID);

   //check balances
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 70 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 20 * COIN);

   {
      auto snapshot = theBDMt_->bdm()->zeroConfCont()->getSnapshot();
      auto zcTxios = snapshot->getTxioMapForScrAddr(TestChain::scrAddrD);
      ASSERT_TRUE(zcTxios.empty());
   }
   
   iface_->getStoredScriptHistory(ssh, TestChain::scrAddrD);
   EXPECT_EQ(ssh.getScriptBalance(), 65 * COIN);

   {   
      auto snapshot = theBDMt_->bdm()->zeroConfCont()->getSnapshot();
      auto zcTxios = snapshot->getTxioMapForScrAddr(TestChain::scrAddrF);
      EXPECT_TRUE(zcTxios.empty());
   }

   iface_->getStoredScriptHistory(ssh, TestChain::scrAddrF);
   EXPECT_EQ(ssh.getScriptBalance(), 5 * COIN);

   //try to get ledgers, ZCs should be all gone
   zcledger = DBTestUtils::getLedgerEntryFromWallet(wlt, ZChash1);
   EXPECT_EQ(zcledger.getTxHash(), BtcUtils::EmptyHash());
   
   zcledger = DBTestUtils::getLedgerEntryFromWallet(wlt, ZChash2);
   EXPECT_EQ(zcledger.getTxTime(), 1231009513);
   EXPECT_EQ(zcledger.getBlockNum(), 5);
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_Supernode, RegisterAfterZC)
{
   TestUtils::setBlocks({ "0", "1", "2", "3", "4" }, blk0dat_);

   theBDMt_->start(DBSettings::initMode());
   auto&& bdvID = DBTestUtils::registerBDV(clients_, BitcoinSettings::getMagicBytes());

   vector<BinaryData> scrAddrVec;
   scrAddrVec.push_back(TestChain::scrAddrA);
   scrAddrVec.push_back(TestChain::scrAddrB);
   scrAddrVec.push_back(TestChain::scrAddrC);
   DBTestUtils::registerWallet(clients_, bdvID, scrAddrVec, "wallet1");

   auto bdvPtr = DBTestUtils::getBDV(clients_, bdvID);

   //wait on signals
   DBTestUtils::goOnline(clients_, bdvID);
   DBTestUtils::waitOnBDMReady(clients_, bdvID);
   auto wlt = bdvPtr->getWalletOrLockbox(wallet1id);
   auto delegateID = DBTestUtils::getLedgerDelegate(clients_, bdvID);

   //check balances
   const ScrAddrObj* scrObj;
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 10 * COIN);

   StoredScriptHistory ssh;
   iface_->getStoredScriptHistory(ssh, TestChain::scrAddrD);
   EXPECT_EQ(ssh.getScriptBalance(), 60 * COIN);
   iface_->getStoredScriptHistory(ssh, TestChain::scrAddrF);
   EXPECT_EQ(ssh.getScriptBalance(), 10 * COIN);

   //Create zc that spends from addr D to F. This is supernode so the DB
   //should track this ZC even though it isn't registered. Send the ZC as
   //a batch along with a ZC that hits our wallets, in order to get the
   //notification, which comes at the BDV level (i.e. only for registered
   //wallets).

   auto&& ZC1 = TestUtils::getTx(5, 2); //block 5, tx 2
   auto&& ZChash1 = BtcUtils::getHash256(ZC1);

   auto&& ZC2 = TestUtils::getTx(5, 1); //block 5, tx 1
   auto&& ZChash2 = BtcUtils::getHash256(ZC2);

   DBTestUtils::ZcVector zcVec1;
   zcVec1.push_back(ZC1, 14000000);
   zcVec1.push_back(ZC2, 14100000);

   DBTestUtils::pushNewZc(theBDMt_, zcVec1);
   DBTestUtils::waitOnNewZcSignal(clients_, bdvID);

   //check balances
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 20 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 20 * COIN);

   try
   {
      auto snapshot = theBDMt_->bdm()->zeroConfCont()->getSnapshot();
      auto zcTxios = snapshot->getTxioMapForScrAddr(TestChain::scrAddrD);
      iface_->getStoredScriptHistory(ssh, TestChain::scrAddrD);
      DBTestUtils::addTxioToSsh(ssh, zcTxios);
      EXPECT_EQ(ssh.getScriptBalance(), 65 * COIN);
   }
   catch (exception&)
   {
      ASSERT_TRUE(false);
   }

   try
   {
      auto snapshot = theBDMt_->bdm()->zeroConfCont()->getSnapshot();
      auto zcTxios = snapshot->getTxioMapForScrAddr(TestChain::scrAddrF);
      iface_->getStoredScriptHistory(ssh, TestChain::scrAddrF);
      DBTestUtils::addTxioToSsh(ssh, zcTxios);
      EXPECT_EQ(ssh.getScriptBalance(), 5 * COIN);
   }
   catch (exception&)
   {
      ASSERT_TRUE(false);
   }

   //Register scrAddrD with the wallet. It should have the ZC balance
   scrAddrVec.push_back(TestChain::scrAddrD);
   DBTestUtils::registerWallet(clients_, bdvID, scrAddrVec, "wallet1");
   
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrD);
   EXPECT_EQ(scrObj->getFullBalance(), 65 * COIN);

   //add last block
   TestUtils::setBlocks({ "0", "1", "2", "3", "4", "5" }, blk0dat_);
   DBTestUtils::triggerNewBlockNotification(theBDMt_);
   DBTestUtils::waitOnNewBlockSignal(clients_, bdvID);

   //check balances
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 70 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 20 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrD);
   EXPECT_EQ(scrObj->getFullBalance(), 65 * COIN);
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_Supernode, ZC_Reorg)
{
   //create spender lamba
   auto getSpenderPtr = [](
      const UnspentTxOut& utxo)
      ->shared_ptr<ScriptSpender>
   {
      UTXO entry(utxo.value_, utxo.txHeight_, utxo.txIndex_, utxo.txOutIndex_,
         move(utxo.txHash_), move(utxo.script_));

      return make_shared<ScriptSpender>(entry);
   };

   //
   TestUtils::setBlocks({ "0", "1", "2", "3", "4", "5" }, blk0dat_);
   theBDMt_->start(DBSettings::initMode());
   auto&& bdvID = DBTestUtils::registerBDV(clients_, BitcoinSettings::getMagicBytes());

   auto&& wltRoot = CryptoPRNG::generateRandom(32);
   auto assetWlt = AssetWallet_Single::createFromPrivateRoot_Armory135(
      homedir_,
      move(wltRoot), //root as a rvalue
      {},
      SecureBinaryData(),
      SecureBinaryData(),
      3); //set lookup computation to 3 entries
   auto addr1_ptr = assetWlt->getNewAddress();
   auto addr2_ptr = assetWlt->getNewAddress();

   vector<BinaryData> scrAddrVec;
   scrAddrVec.push_back(TestChain::scrAddrA);
   scrAddrVec.push_back(TestChain::scrAddrB);
   scrAddrVec.push_back(TestChain::scrAddrC);
   
   auto&& wltSet = assetWlt->getAddrHashSet();
   vector<BinaryData> wltVec;
   for (auto& addr : wltSet)
      wltVec.push_back(addr);

   DBTestUtils::registerWallet(clients_, bdvID, scrAddrVec, "wallet1");
   DBTestUtils::registerWallet(clients_, bdvID, wltVec, assetWlt->getID());
   auto bdvPtr = DBTestUtils::getBDV(clients_, bdvID);

   //wait on signals
   DBTestUtils::goOnline(clients_, bdvID);
   DBTestUtils::waitOnBDMReady(clients_, bdvID);
   auto wlt = bdvPtr->getWalletOrLockbox(wallet1id);
   auto assetWltDbObj = bdvPtr->getWalletOrLockbox(assetWlt->getID());
   auto delegateID = DBTestUtils::getLedgerDelegate(clients_, bdvID);

   //check balances
   const ScrAddrObj* scrObj;
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 70 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 20 * COIN);

   BinaryData ZCHash1, ZCHash2;
   for (auto& sa : wltSet)
   {
      scrObj = assetWltDbObj->getScrAddrObjByKey(sa);
      EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   }

   {
      Signer signer;

      //instantiate resolver feed overloaded object
      auto feed = make_shared<ResolverUtils::TestResolverFeed>();
      feed->addPrivKey(TestChain::privKeyAddrB);
      feed->addPrivKey(TestChain::privKeyAddrC);
      feed->addPrivKey(TestChain::privKeyAddrD);
      feed->addPrivKey(TestChain::privKeyAddrE);
      feed->addPrivKey(TestChain::privKeyAddrF);

      //get utxo list for spend value
      auto&& unspentVec = wlt->getSpendableTxOutListForValue(UINT64_MAX);

      //consume 1st utxo, send 2 to scrAddrA, 3 to new wallet
      signer.addSpender(getSpenderPtr(unspentVec[0]));
      signer.addRecipient(addr1_ptr->getRecipient(3 * COIN));
      auto recipientChange = make_shared<Recipient_P2PKH>(
         TestChain::scrAddrA.getSliceCopy(1, 20), 2 * COIN);
      signer.addRecipient(recipientChange);
      signer.setFeed(feed);
      signer.sign();

      //2nd tx, 2nd utxo, 5 to scrAddrB, 5 new wallet
      Signer signer2;
      signer2.addSpender(getSpenderPtr(unspentVec[1]));
      signer2.addRecipient(addr2_ptr->getRecipient(5 * COIN));
      auto recipientChange2 = make_shared<Recipient_P2PKH>(
         TestChain::scrAddrB.getSliceCopy(1, 20), 5 * COIN);
      signer2.addRecipient(recipientChange2);
      signer2.setFeed(feed);
      signer2.sign();

      DBTestUtils::ZcVector zcVec;
      zcVec.push_back(signer.serializeSignedTx(), 14000000);
      ZCHash1 = zcVec.zcVec_.back().first.getThisHash();

      zcVec.push_back(signer2.serializeSignedTx(), 14100000);
      ZCHash2 = zcVec.zcVec_.back().first.getThisHash();

      DBTestUtils::pushNewZc(theBDMt_, zcVec);
      DBTestUtils::waitOnNewZcSignal(clients_, bdvID);
   }

   //check balances
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 52 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 75 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);

   scrObj = assetWltDbObj->getScrAddrObjByKey(addr1_ptr->getPrefixedHash());
   EXPECT_EQ(scrObj->getFullBalance(), 3 * COIN);
   scrObj = assetWltDbObj->getScrAddrObjByKey(addr2_ptr->getPrefixedHash());
   EXPECT_EQ(scrObj->getFullBalance(), 5 * COIN);

   //reorg the chain
   TestUtils::setBlocks({ "0", "1", "2", "3", "4", "5", "4A", "5A" }, blk0dat_);
   DBTestUtils::triggerNewBlockNotification(theBDMt_);
   auto&& newBlockNotif = DBTestUtils::waitOnNewBlockSignal(clients_, bdvID);
   
   //check new block callback carries an invalidated zc notif as well
   auto notifPtr = get<0>(newBlockNotif);
   auto notifIndex = get<1>(newBlockNotif);

   EXPECT_EQ(notifIndex, 0);
   ASSERT_EQ(notifPtr->notification_size(), 2);

   //grab the invalidated zc notif, it should carry the hash for both our ZC
   auto& zcNotif = notifPtr->notification(1);
   EXPECT_EQ(zcNotif.type(), ::Codec_BDVCommand::NotificationType::invalidated_zc);
   EXPECT_TRUE(zcNotif.has_ids());
   
   auto& ids = zcNotif.ids();
   EXPECT_EQ(ids.value_size(), 2);
   
   //check zc hash 1
   auto& id0_str = ids.value(0).data();
   BinaryData id0_bd((uint8_t*)id0_str.c_str(), id0_str.size());
   EXPECT_EQ(ZCHash1, id0_bd);

   //check zc hash 2
   auto& id1_str = ids.value(1).data();
   BinaryData id1_bd((uint8_t*)id1_str.c_str(), id1_str.size());
   EXPECT_EQ(ZCHash2, id1_bd);


   //check balances
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 55 * COIN);

   scrObj = assetWltDbObj->getScrAddrObjByKey(addr1_ptr->getPrefixedHash());
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   scrObj = assetWltDbObj->getScrAddrObjByKey(addr2_ptr->getPrefixedHash());
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_Supernode, ChainZC_RBFchild_Test)
{
   //create spender lambda
   auto getSpenderPtr = [](
      const UnspentTxOut& utxo, bool flagRBF)
      ->shared_ptr<ScriptSpender>
   {
      UTXO entry(utxo.value_, utxo.txHeight_, utxo.txIndex_, utxo.txOutIndex_,
         move(utxo.txHash_), move(utxo.script_));

      auto spender = make_shared<ScriptSpender>(entry);

      if (flagRBF)
         spender->setSequence(UINT32_MAX - 2);

      return spender;
   };

   BinaryData ZCHash1, ZCHash2, ZCHash3;

   //
   TestUtils::setBlocks({ "0", "1", "2", "3" }, blk0dat_);

   theBDMt_->start(DBSettings::initMode());
   auto&& bdvID = DBTestUtils::registerBDV(clients_, BitcoinSettings::getMagicBytes());

   vector<BinaryData> scrAddrVec;
   scrAddrVec.push_back(TestChain::scrAddrA);
   scrAddrVec.push_back(TestChain::scrAddrB);
   scrAddrVec.push_back(TestChain::scrAddrC);
   scrAddrVec.push_back(TestChain::scrAddrD);
   scrAddrVec.push_back(TestChain::scrAddrE);

   //// create assetWlt ////

   //create a root private key
   auto&& wltRoot = CryptoPRNG::generateRandom(32);
   auto assetWlt = AssetWallet_Single::createFromPrivateRoot_Armory135(
      homedir_,
      move(wltRoot), //root as a r value
      {},
      SecureBinaryData(),
      SecureBinaryData(), 
      10); //set lookup computation to 5 entries

   //register with db
   vector<BinaryData> addrVec;

   auto hashSet = assetWlt->getAddrHashSet();
   vector<BinaryData> hashVec;
   hashVec.insert(hashVec.begin(), hashSet.begin(), hashSet.end());

   DBTestUtils::registerWallet(clients_, bdvID, hashVec, assetWlt->getID());
   DBTestUtils::registerWallet(clients_, bdvID, scrAddrVec, "wallet1");

   auto bdvPtr = DBTestUtils::getBDV(clients_, bdvID);

   //wait on signals
   DBTestUtils::goOnline(clients_, bdvID);
   DBTestUtils::waitOnBDMReady(clients_, bdvID);
   EXPECT_EQ(DBTestUtils::getTopBlockHeight(iface_, HEADERS), 3);

   auto wlt = bdvPtr->getWalletOrLockbox(wallet1id);
   auto dbAssetWlt = bdvPtr->getWalletOrLockbox(assetWlt->getID());

   //check balances
   const ScrAddrObj* scrObj;
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 55 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrD);
   EXPECT_EQ(scrObj->getFullBalance(), 5 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrE);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);

   //check new wallet balances
   for (auto& scripthash : hashSet)
   {
      scrObj = dbAssetWlt->getScrAddrObjByKey(scripthash);
      EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   }

   {
      ////spend 27 from wlt to assetWlt's first 2 unused addresses
      ////send change back to scrAddrD

      auto spendVal = 27 * COIN;
      Signer signer;

      //instantiate resolver feed overloaded object
      auto feed = make_shared<ResolverUtils::TestResolverFeed>();
      feed->addPrivKey(TestChain::privKeyAddrB);
      feed->addPrivKey(TestChain::privKeyAddrC);
      feed->addPrivKey(TestChain::privKeyAddrD);
      feed->addPrivKey(TestChain::privKeyAddrE);

      //get utxo list for spend value
      auto&& unspentVec = wlt->getSpendableTxOutListForValue(spendVal);

      vector<UnspentTxOut> utxoVec;
      uint64_t tval = 0;
      auto utxoIter = unspentVec.begin();
      while (utxoIter != unspentVec.end())
      {
         tval += utxoIter->getValue();
         utxoVec.push_back(*utxoIter);

         if (tval > spendVal)
            break;

         ++utxoIter;
      }

      //create script spender objects
      uint64_t total = 0;
      for (auto& utxo : utxoVec)
      {
         total += utxo.getValue();
         signer.addSpender(getSpenderPtr(utxo, true));
      }

      //spend 12 to first address
      auto addr0 = assetWlt->getNewAddress();
      signer.addRecipient(addr0->getRecipient(12 * COIN));
      addrVec.push_back(addr0->getPrefixedHash());

      //spend 15 to addr 1, use P2PKH
      auto addr1 = assetWlt->getNewAddress();
      signer.addRecipient(addr1->getRecipient(15 * COIN));
      addrVec.push_back(addr1->getPrefixedHash());

      if (total > spendVal)
      {
         //deal with change, no fee
         auto changeVal = total - spendVal;
         auto recipientChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrD.getSliceCopy(1, 20), changeVal);
         signer.addRecipient(recipientChange);
      }

      //sign, verify then broadcast
      signer.setFeed(feed);
      signer.sign();
      EXPECT_TRUE(signer.verify());

      auto rawTx = signer.serializeSignedTx();
      DBTestUtils::ZcVector zcVec;
      zcVec.push_back(rawTx, 14000000);

      ZCHash1 = move(BtcUtils::getHash256(rawTx));
      DBTestUtils::pushNewZc(theBDMt_, zcVec);
      DBTestUtils::waitOnNewZcSignal(clients_, bdvID);
   }

   //check balances
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 55 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrD);
   EXPECT_EQ(scrObj->getFullBalance(), 8 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrE);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);

   //check new wallet balances
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[0]);
   EXPECT_EQ(scrObj->getFullBalance(), 12 * COIN);
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[1]);
   EXPECT_EQ(scrObj->getFullBalance(), 15 * COIN);

   //grab ledger
   auto zcledger = DBTestUtils::getLedgerEntryFromWallet(dbAssetWlt, ZCHash1);
   EXPECT_EQ(zcledger.getValue(), 27 * COIN);
   //EXPECT_EQ(zcledger.getTxTime(), 14000000);
   EXPECT_TRUE(zcledger.isOptInRBF());

   //cpfp the first zc
   {
      Signer signer3;

      //instantiate resolver feed overloaded object
      auto assetFeed = make_shared<ResolverFeed_AssetWalletSingle>(assetWlt);

      //get utxo list for spend value
      auto&& unspentVec = dbAssetWlt->getSpendableTxOutListZC();

      //create script spender objects
      uint64_t total = 0;
      for (auto& utxo : unspentVec)
      {
         total += utxo.getValue();
         signer3.addSpender(getSpenderPtr(utxo, true));
      }

      //spend 4 to a new address
      auto addr0 = assetWlt->getNewAddress();
      signer3.addRecipient(addr0->getRecipient(4 * COIN));
      addrVec.push_back(addr0->getPrefixedHash());

      //spend 6 to a new address
      auto addr1 = assetWlt->getNewAddress();
      signer3.addRecipient(addr1->getRecipient(6 * COIN));
      addrVec.push_back(addr1->getPrefixedHash());

      //deal with change, no fee
      auto changeVal = total - 10 * COIN;
      auto recipientChange = make_shared<Recipient_P2PKH>(
         TestChain::scrAddrD.getSliceCopy(1, 20), changeVal);
      signer3.addRecipient(recipientChange);

      //sign, verify then broadcast
      {
         auto lock = assetWlt->lockDecryptedContainer();
         signer3.setFeed(assetFeed);
         signer3.sign();
      }

      auto rawTx = signer3.serializeSignedTx();
      DBTestUtils::ZcVector zcVec3;
      zcVec3.push_back(rawTx, 15000000);

      ZCHash2 = move(BtcUtils::getHash256(rawTx));
      DBTestUtils::pushNewZc(theBDMt_, zcVec3);
      DBTestUtils::waitOnNewZcSignal(clients_, bdvID);
   }

   //check balances
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 55 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrD);
   EXPECT_EQ(scrObj->getFullBalance(), 25 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrE);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);

   //check new wallet balances
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[0]);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[1]);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[2]);
   EXPECT_EQ(scrObj->getFullBalance(), 4 * COIN);
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[3]);
   EXPECT_EQ(scrObj->getFullBalance(), 6 * COIN);


   //grab ledgers

   //first zc should be valid still
   auto zcledger1 = DBTestUtils::getLedgerEntryFromWallet(dbAssetWlt, ZCHash1);
   EXPECT_EQ(zcledger1.getValue(), 27 * COIN);
   //EXPECT_EQ(zcledger1.getTxTime(), 14000000);
   EXPECT_TRUE(zcledger1.isOptInRBF());

   //second zc should be valid
   auto zcledger2 = DBTestUtils::getLedgerEntryFromWallet(dbAssetWlt, ZCHash2);
   EXPECT_EQ(zcledger2.getValue(), -17 * COIN);
   //EXPECT_EQ(zcledger2.getTxTime(), 15000000);
   EXPECT_TRUE(zcledger2.isOptInRBF());

   //rbf the child
   {
      auto spendVal = 10 * COIN;
      Signer signer2;

      //instantiate resolver feed
      auto assetFeed =
         make_shared<ResolverFeed_AssetWalletSingle>(assetWlt);

      //get utxo list for spend value
      auto&& unspentVec = dbAssetWlt->getRBFTxOutList();

      vector<UnspentTxOut> utxoVec;
      uint64_t tval = 0;
      auto utxoIter = unspentVec.begin();
      while (utxoIter != unspentVec.end())
      {
         tval += utxoIter->getValue();
         utxoVec.push_back(*utxoIter);

         if (tval > spendVal)
            break;

         ++utxoIter;
      }

      //create script spender objects
      uint64_t total = 0;
      for (auto& utxo : utxoVec)
      {
         total += utxo.getValue();
         signer2.addSpender(getSpenderPtr(utxo, true));
      }

      //spend 6 to a new address
      auto addr0 = assetWlt->getNewAddress();
      signer2.addRecipient(addr0->getRecipient(6 * COIN));
      addrVec.push_back(addr0->getPrefixedHash());


      if (total > spendVal)
      {
         //change addrE, 1 btc fee
         auto changeVal = 5 * COIN;
         auto recipientChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrE.getSliceCopy(1, 20), changeVal);
         signer2.addRecipient(recipientChange);
      }

      //sign, verify then broadcast
      {
         auto lock = assetWlt->lockDecryptedContainer();
         signer2.setFeed(assetFeed);
         signer2.sign();
      }
      EXPECT_TRUE(signer2.verify());

      auto rawTx = signer2.serializeSignedTx();
      DBTestUtils::ZcVector zcVec2;
      zcVec2.push_back(rawTx, 17000000);

      ZCHash3 = move(BtcUtils::getHash256(rawTx));
      DBTestUtils::pushNewZc(theBDMt_, zcVec2);
      DBTestUtils::waitOnNewZcSignal(clients_, bdvID);
   }

   //check balances
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 55 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrD);
   EXPECT_EQ(scrObj->getFullBalance(), 8 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrE);
   EXPECT_EQ(scrObj->getFullBalance(), 5 * COIN);

   //check new wallet balances
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[0]);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[1]);
   EXPECT_EQ(scrObj->getFullBalance(), 15 * COIN);
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[2]);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[3]);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[4]);
   EXPECT_EQ(scrObj->getFullBalance(), 6 * COIN);

   //grab ledgers

   //first zc should be replaced, hence the ledger should be empty
   auto zcledger3 = DBTestUtils::getLedgerEntryFromWallet(dbAssetWlt, ZCHash1);
   EXPECT_EQ(zcledger3.getValue(), 27 * COIN);
   EXPECT_EQ(zcledger3.getBlockNum(), UINT32_MAX);
   EXPECT_TRUE(zcledger3.isOptInRBF());

   //second zc should be replaced
   auto zcledger8 = DBTestUtils::getLedgerEntryFromWallet(dbAssetWlt, ZCHash2);
   EXPECT_EQ(zcledger8.getTxHash(), BtcUtils::EmptyHash_);

   //third zc should be valid
   auto zcledger9 = DBTestUtils::getLedgerEntryFromWallet(dbAssetWlt, ZCHash3);
   EXPECT_EQ(zcledger9.getValue(), -6 * COIN);
   EXPECT_EQ(zcledger9.getBlockNum(), UINT32_MAX);
   EXPECT_TRUE(zcledger9.isOptInRBF());

   //mine a new block
   DBTestUtils::mineNewBlock(theBDMt_, TestChain::addrA, 3);
   DBTestUtils::waitOnNewBlockSignal(clients_, bdvID);

   //check chain is 3 block longer
   EXPECT_EQ(DBTestUtils::getTopBlockHeight(iface_, HEADERS), 6);

   //check balances
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 200 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 30 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 55 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrD);
   EXPECT_EQ(scrObj->getFullBalance(), 8 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrE);
   EXPECT_EQ(scrObj->getFullBalance(), 5 * COIN);

   //check new wallet balances
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[0]);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[1]);
   EXPECT_EQ(scrObj->getFullBalance(), 15 * COIN);
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[2]);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[3]);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
   scrObj = dbAssetWlt->getScrAddrObjByKey(addrVec[4]);
   EXPECT_EQ(scrObj->getFullBalance(), 6 * COIN);

   //check all zc are mined with 1 conf
   zcledger3 = DBTestUtils::getLedgerEntryFromWallet(dbAssetWlt, ZCHash1);
   EXPECT_EQ(zcledger3.getValue(), 27 * COIN);
   EXPECT_EQ(zcledger3.getBlockNum(), 4);
   EXPECT_FALSE(zcledger3.isOptInRBF());

   zcledger9 = DBTestUtils::getLedgerEntryFromWallet(dbAssetWlt, ZCHash3);
   EXPECT_EQ(zcledger9.getValue(), -6 * COIN);
   EXPECT_EQ(zcledger9.getBlockNum(), 4);
   EXPECT_FALSE(zcledger9.isOptInRBF());
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_Supernode, ZC_InOut_SameBlock)
{
   BinaryData ZCHash1, ZCHash2, ZCHash3;

   //
   TestUtils::setBlocks({ "0", "1" }, blk0dat_);

   theBDMt_->start(DBSettings::initMode());
   auto&& bdvID = DBTestUtils::registerBDV(clients_, BitcoinSettings::getMagicBytes());

   vector<BinaryData> scrAddrVec;
   scrAddrVec.push_back(TestChain::scrAddrA);
   scrAddrVec.push_back(TestChain::scrAddrB);
   scrAddrVec.push_back(TestChain::scrAddrC);

   DBTestUtils::registerWallet(clients_, bdvID, scrAddrVec, "wallet1");

   auto bdvPtr = DBTestUtils::getBDV(clients_, bdvID);

   //wait on signals
   DBTestUtils::goOnline(clients_, bdvID);
   DBTestUtils::waitOnBDMReady(clients_, bdvID);
   auto wlt = bdvPtr->getWalletOrLockbox(wallet1id);

   //check balances
   const ScrAddrObj* scrObj;
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);

   //add the 2 zc
   auto&& ZC1 = TestUtils::getTx(2, 1); //block 2, tx 1
   auto&& ZChash1 = BtcUtils::getHash256(ZC1);

   auto&& ZC2 = TestUtils::getTx(2, 2); //block 2, tx 2
   auto&& ZChash2 = BtcUtils::getHash256(ZC2);

   DBTestUtils::ZcVector rawZcVec;
   rawZcVec.push_back(ZC1, 1300000000);
   rawZcVec.push_back(ZC2, 1310000000);

   DBTestUtils::pushNewZc(theBDMt_, rawZcVec);
   DBTestUtils::waitOnNewZcSignal(clients_, bdvID);

   //check balances
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 5 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);

   //add last block
   TestUtils::appendBlocks({ "2" }, blk0dat_);
   DBTestUtils::triggerNewBlockNotification(theBDMt_);
   DBTestUtils::waitOnNewBlockSignal(clients_, bdvID);

   //check balances
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrA);
   EXPECT_EQ(scrObj->getFullBalance(), 50 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrB);
   EXPECT_EQ(scrObj->getFullBalance(), 55 * COIN);
   scrObj = wlt->getScrAddrObjByKey(TestChain::scrAddrC);
   EXPECT_EQ(scrObj->getFullBalance(), 0 * COIN);
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_Supernode, ZC_MineAfter1Block)
{
   auto feed = make_shared<ResolverUtils::TestResolverFeed>();
   feed->addPrivKey(TestChain::privKeyAddrB);
   feed->addPrivKey(TestChain::privKeyAddrC);
   feed->addPrivKey(TestChain::privKeyAddrD);

   ////
   vector<BinaryData> scrAddrVec;
   scrAddrVec.push_back(TestChain::scrAddrA);
   scrAddrVec.push_back(TestChain::scrAddrB);
   scrAddrVec.push_back(TestChain::scrAddrC);
   scrAddrVec.push_back(TestChain::scrAddrD);

   theBDMt_->start(DBSettings::initMode());
   auto&& bdvID = DBTestUtils::registerBDV(clients_, BitcoinSettings::getMagicBytes());

   DBTestUtils::registerWallet(clients_, bdvID, scrAddrVec, "wallet1");

   auto bdvPtr = DBTestUtils::getBDV(clients_, bdvID);

   //wait on signals
   DBTestUtils::goOnline(clients_, bdvID);
   DBTestUtils::waitOnBDMReady(clients_, bdvID);
   auto wlt = bdvPtr->getWalletOrLockbox(wallet1id);

   uint64_t balanceWlt;

   balanceWlt = wlt->getScrAddrObjByKey(TestChain::scrAddrA)->getFullBalance();
   EXPECT_EQ(balanceWlt, 50 * COIN);

   balanceWlt = wlt->getScrAddrObjByKey(TestChain::scrAddrB)->getFullBalance();
   EXPECT_EQ(balanceWlt, 70 * COIN);

   balanceWlt = wlt->getScrAddrObjByKey(TestChain::scrAddrC)->getFullBalance();
   EXPECT_EQ(balanceWlt, 20 * COIN);

   balanceWlt = wlt->getScrAddrObjByKey(TestChain::scrAddrD)->getFullBalance();
   EXPECT_EQ(balanceWlt, 65 * COIN);

   //spend from B to C
   auto&& utxoVec = wlt->getSpendableTxOutListForValue();

   UTXO utxoA, utxoB;
   for (auto& utxo : utxoVec)
   {
      if (utxo.getRecipientScrAddr() == TestChain::scrAddrD)
      {
         utxoA.value_ = utxo.value_;
         utxoA.script_ = utxo.script_;
         utxoA.txHeight_ = utxo.txHeight_;
         utxoA.txIndex_ = utxo.txIndex_;
         utxoA.txOutIndex_ = utxo.txOutIndex_;
         utxoA.txHash_ = utxo.txHash_;
      }
      else if (utxo.getRecipientScrAddr() == TestChain::scrAddrB)
      {
         utxoB.value_ = utxo.value_;
         utxoB.script_ = utxo.script_;
         utxoB.txHeight_ = utxo.txHeight_;
         utxoB.txIndex_ = utxo.txIndex_;
         utxoB.txOutIndex_ = utxo.txOutIndex_;
         utxoB.txHash_ = utxo.txHash_;
      }
   }

   auto spenderA = make_shared<ScriptSpender>(utxoA);
   auto spenderB = make_shared<ScriptSpender>(utxoB);

   DBTestUtils::ZcVector zcVec;

   //spend from D to C
   {
      Signer signer;
      signer.addSpender(spenderA);

      auto recipient = std::make_shared<Recipient_P2PKH>(
         TestChain::scrAddrC.getSliceCopy(1, 20), utxoA.getValue());
      signer.addRecipient(recipient);

      signer.setFeed(feed);
      signer.sign();
      auto rawTx = signer.serializeSignedTx();
      zcVec.push_back(signer.serializeSignedTx(), 130000000, 0);
   }
   
   //spend from B to C
   {
      Signer signer;
      signer.addSpender(spenderB);

      auto recipient = std::make_shared<Recipient_P2PKH>(
         TestChain::scrAddrC.getSliceCopy(1, 20), utxoB.getValue());
      signer.addRecipient(recipient);

      signer.setFeed(feed);
      signer.sign();
      zcVec.push_back(signer.serializeSignedTx(), 131000000, 1);
   }

   auto hash1 = zcVec.zcVec_[0].first.getThisHash();
   auto hash2 = zcVec.zcVec_[1].first.getThisHash();

   //broadcast
   DBTestUtils::pushNewZc(theBDMt_, zcVec);
   DBTestUtils::waitOnNewZcSignal(clients_, bdvID);

   //check balances
   balanceWlt = wlt->getScrAddrObjByKey(TestChain::scrAddrA)->getFullBalance();
   EXPECT_EQ(balanceWlt, 50 * COIN);

   balanceWlt = wlt->getScrAddrObjByKey(TestChain::scrAddrB)->getFullBalance();
   EXPECT_EQ(balanceWlt, 50 * COIN);

   balanceWlt = wlt->getScrAddrObjByKey(TestChain::scrAddrC)->getFullBalance();
   EXPECT_EQ(balanceWlt, 45 * COIN);

   balanceWlt = wlt->getScrAddrObjByKey(TestChain::scrAddrD)->getFullBalance();
   EXPECT_EQ(balanceWlt, 60 * COIN);

   auto zc1 = bdvPtr->getTxByHash(hash1);
   auto zc2 = bdvPtr->getTxByHash(hash2);

   EXPECT_EQ(zc1.getTxHeight(), UINT32_MAX);
   EXPECT_EQ(zc2.getTxHeight(), UINT32_MAX);

   //mine 1 block
   DBTestUtils::mineNewBlock(theBDMt_, TestChain::addrA, 1);
   DBTestUtils::waitOnNewBlockSignal(clients_, bdvID);

   //check balances
   balanceWlt = wlt->getScrAddrObjByKey(TestChain::scrAddrA)->getFullBalance();
   EXPECT_EQ(balanceWlt, 100 * COIN);

   balanceWlt = wlt->getScrAddrObjByKey(TestChain::scrAddrB)->getFullBalance();
   EXPECT_EQ(balanceWlt, 50 * COIN);

   balanceWlt = wlt->getScrAddrObjByKey(TestChain::scrAddrC)->getFullBalance();
   EXPECT_EQ(balanceWlt, 45 * COIN);

   balanceWlt = wlt->getScrAddrObjByKey(TestChain::scrAddrD)->getFullBalance();
   EXPECT_EQ(balanceWlt, 60 * COIN);

   zc1 = bdvPtr->getTxByHash(hash1);
   zc2 = bdvPtr->getTxByHash(hash2);

   EXPECT_EQ(zc1.getTxHeight(), 6);
   EXPECT_EQ(zc2.getTxHeight(), UINT32_MAX);

   //mine last block
   DBTestUtils::mineNewBlock(theBDMt_, TestChain::addrB, 1);
   DBTestUtils::waitOnNewBlockSignal(clients_, bdvID);

   //check balances
   balanceWlt = wlt->getScrAddrObjByKey(TestChain::scrAddrA)->getFullBalance();
   EXPECT_EQ(balanceWlt, 100 * COIN);

   balanceWlt = wlt->getScrAddrObjByKey(TestChain::scrAddrB)->getFullBalance();
   EXPECT_EQ(balanceWlt, 100 * COIN);

   balanceWlt = wlt->getScrAddrObjByKey(TestChain::scrAddrC)->getFullBalance();
   EXPECT_EQ(balanceWlt, 45 * COIN);

   balanceWlt = wlt->getScrAddrObjByKey(TestChain::scrAddrD)->getFullBalance();
   EXPECT_EQ(balanceWlt, 60 * COIN);

   zc1 = bdvPtr->getTxByHash(hash1);
   zc2 = bdvPtr->getTxByHash(hash2);

   EXPECT_EQ(zc1.getTxHeight(), 6);
   EXPECT_EQ(zc2.getTxHeight(), 7);
}


////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
class ZeroConfTests_Supernode_WebSocket : public ::testing::Test
{
protected:
   BlockDataManagerThread *theBDMt_;
   PassphraseLambda authPeersPassLbd_;

   void initBDM(void)
   {
      theBDMt_ = new BlockDataManagerThread();
      iface_ = theBDMt_->bdm()->getIFace();

      nodePtr_ = dynamic_pointer_cast<NodeUnitTest>(
         NetworkSettings::bitcoinNodes().first);

      rpcNode_ = dynamic_pointer_cast<NodeRPC_UnitTest>(
         NetworkSettings::rpcNode());

      nodePtr_->setIface(iface_);
      nodePtr_->setBlockchain(theBDMt_->bdm()->blockchain());
      nodePtr_->setBlockFiles(theBDMt_->bdm()->blockFiles());
   }

   /////////////////////////////////////////////////////////////////////////////
   virtual void SetUp()
   {
      LOGDISABLESTDOUT();
      zeros_ = READHEX("00000000");

      blkdir_ = string("./blkfiletest");
      homedir_ = string("./fakehomedir");
      ldbdir_ = string("./ldbtestdir");

      DBUtils::removeDirectory(blkdir_);
      DBUtils::removeDirectory(homedir_);
      DBUtils::removeDirectory(ldbdir_);

      mkdir(blkdir_ + "/blocks");
      mkdir(homedir_);
      mkdir(ldbdir_);

      // Put the first 5 blocks into the blkdir
      blk0dat_ = BtcUtils::getBlkFilename(blkdir_ + "/blocks", 0);
      TestUtils::setBlocks({ "0", "1", "2", "3", "4", "5" }, blk0dat_);

      startupBIP151CTX();
      startupBIP150CTX(4);

      DBSettings::setServiceType(SERVICE_UNITTEST_WITHWS);
      ArmoryConfig::parseArgs({
         "--datadir=./fakehomedir",
         "--dbdir=./ldbtestdir",
         "--satoshi-datadir=./blkfiletest",
         "--db-type=DB_SUPER",
         "--thread-count=3",
         "--public",
         "--cookie"
      });

      //setup auth peers for server and client
      authPeersPassLbd_ = [](const set<BinaryData>&)->SecureBinaryData
      {
         return SecureBinaryData::fromString("authpeerpass");
      };

      AuthorizedPeers serverPeers(
         homedir_, SERVER_AUTH_PEER_FILENAME, authPeersPassLbd_);
      AuthorizedPeers clientPeers(
         homedir_, CLIENT_AUTH_PEER_FILENAME, authPeersPassLbd_);

      //share public keys between client and server
      auto& serverPubkey = serverPeers.getOwnPublicKey();
      auto& clientPubkey = clientPeers.getOwnPublicKey();

      stringstream serverAddr;
      serverAddr << "127.0.0.1:" << NetworkSettings::listenPort();
      clientPeers.addPeer(serverPubkey, serverAddr.str());
      serverPeers.addPeer(clientPubkey, "127.0.0.1");

      wallet1id = "wallet1";

      initBDM();
   }

   /////////////////////////////////////////////////////////////////////////////
   virtual void TearDown(void)
   {
      shutdownBIP151CTX();
      
      delete theBDMt_;
      theBDMt_ = nullptr;

      DBUtils::removeDirectory(blkdir_);
      DBUtils::removeDirectory(homedir_);
      DBUtils::removeDirectory("./ldbtestdir");

      ArmoryConfig::reset();

      LOGENABLESTDOUT();
      CLEANUP_ALL_TIMERS();
   }

   LMDBBlockDatabase* iface_;
   BinaryData zeros_;

   string blkdir_;
   string homedir_;
   string ldbdir_;
   string blk0dat_;

   string wallet1id;

   shared_ptr<NodeUnitTest> nodePtr_;
   shared_ptr<NodeRPC_UnitTest> rpcNode_;
};

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_Supernode_WebSocket, ZcUpdate)
{
   /*
   Some sigs in static test chain are borked. P2SH scripts are borked too. This
   test plucks transactions from the static chain to push as ZC. Skip sig checks
   on the unit test mock P2P node to avoid faililng the test.
   */
   nodePtr_->checkSigs(false);

   TestUtils::setBlocks({ "0", "1" }, blk0dat_);
   WebSocketServer::initAuthPeers(authPeersPassLbd_);
   WebSocketServer::start(theBDMt_, true);
   auto&& serverPubkey = WebSocketServer::getPublicKey();

   vector<BinaryData> scrAddrVec;
   scrAddrVec.push_back(TestChain::scrAddrA);
   scrAddrVec.push_back(TestChain::scrAddrB);
   scrAddrVec.push_back(TestChain::scrAddrC);

   theBDMt_->start(DBSettings::initMode());

   auto pCallback = make_shared<DBTestUtils::UTCallback>();
   auto bdvObj = AsyncClient::BlockDataViewer::getNewBDV(
      "127.0.0.1", NetworkSettings::listenPort(), 
      ArmoryConfig::getDataDir(),
      authPeersPassLbd_, 
      NetworkSettings::ephemeralPeers(), true, //public server
      pCallback);
   bdvObj->addPublicKey(serverPubkey);
   bdvObj->connectToRemote();
   bdvObj->registerWithDB(BitcoinSettings::getMagicBytes());

   //go online
   bdvObj->goOnline();
   pCallback->waitOnSignal(BDMAction_Ready);

   vector<string> walletRegIDs;

   auto&& wallet1 = bdvObj->instantiateWallet("wallet1");
   walletRegIDs.push_back(
      wallet1.registerAddresses(scrAddrVec, false));

   //wait on registration ack
   pCallback->waitOnManySignals(BDMAction_Refresh, walletRegIDs);

   //get wallets delegate
   auto del1_prom = make_shared<promise<AsyncClient::LedgerDelegate>>();
   auto del1_fut = del1_prom->get_future();
   auto del1_get = [del1_prom](
      ReturnMessage<AsyncClient::LedgerDelegate> delegate)->void
   {
      del1_prom->set_value(move(delegate.get()));
   };
   bdvObj->getLedgerDelegateForWallets(del1_get);
   auto&& main_delegate = del1_fut.get();

   auto ledger_prom =
      make_shared<promise<vector<DBClientClasses::LedgerEntry>>>();
   auto ledger_fut = ledger_prom->get_future();
   auto ledger_get =
      [ledger_prom](
         ReturnMessage<vector<DBClientClasses::LedgerEntry>> ledgerV)->void
   {
      ledger_prom->set_value(move(ledgerV.get()));
   };
   main_delegate.getHistoryPage(0, ledger_get);
   auto&& main_ledger = ledger_fut.get();

   //check ledgers
   EXPECT_EQ(main_ledger.size(), 2);

   EXPECT_EQ(main_ledger[0].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[0].getBlockNum(), 1);
   EXPECT_EQ(main_ledger[0].getIndex(), 0);

   EXPECT_EQ(main_ledger[1].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[1].getBlockNum(), 0);
   EXPECT_EQ(main_ledger[1].getIndex(), 0);

   //add the 2 zc
   auto&& ZC1 = TestUtils::getTx(2, 1); //block 2, tx 1
   auto&& ZChash1 = BtcUtils::getHash256(ZC1);

   auto&& ZC2 = TestUtils::getTx(2, 2); //block 2, tx 2
   auto&& ZChash2 = BtcUtils::getHash256(ZC2);

   vector<BinaryData> zcVec = {ZC1, ZC2};
   auto broadcastID = bdvObj->broadcastZC(zcVec);
   
   {
      set<BinaryData> zcHashes = { ZChash1, ZChash2 };
      set<BinaryData> scrAddrSet;

      Tx zctx1(ZC1);
      for (unsigned i = 0; i < zctx1.getNumTxOut(); i++)
         scrAddrSet.insert(zctx1.getScrAddrForTxOut(i));

      Tx zctx2(ZC2);
      for (unsigned i = 0; i < zctx2.getNumTxOut(); i++)
         scrAddrSet.insert(zctx2.getScrAddrForTxOut(i));

      pCallback->waitOnZc(zcHashes, scrAddrSet, broadcastID);
   }

   //get the new ledgers
   auto ledger2_prom =
      make_shared<promise<vector<DBClientClasses::LedgerEntry>>>();
   auto ledger2_fut = ledger2_prom->get_future();
   auto ledger2_get =
      [ledger2_prom](ReturnMessage<vector<DBClientClasses::LedgerEntry>> ledgerV)->void
   {
      ledger2_prom->set_value(move(ledgerV.get()));
   };
   main_delegate.getHistoryPage(0, ledger2_get);
   main_ledger = move(ledger2_fut.get());

   //check ledgers
   EXPECT_EQ(main_ledger.size(), 4);

   EXPECT_EQ(main_ledger[0].getValue(), -20 * COIN);
   EXPECT_EQ(main_ledger[0].getBlockNum(), UINT32_MAX);
   EXPECT_EQ(main_ledger[0].getIndex(), 1);

   EXPECT_EQ(main_ledger[1].getValue(), -25 * COIN);
   EXPECT_EQ(main_ledger[1].getBlockNum(), UINT32_MAX);
   EXPECT_EQ(main_ledger[1].getIndex(), 0);

   EXPECT_EQ(main_ledger[2].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[2].getBlockNum(), 1);
   EXPECT_EQ(main_ledger[2].getIndex(), 0);

   EXPECT_EQ(main_ledger[3].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[3].getBlockNum(), 0);
   EXPECT_EQ(main_ledger[3].getIndex(), 0);

   //tx cache testing
   //grab ZC1 from async client
   auto zc_prom1 = make_shared<promise<AsyncClient::TxResult>>();
   auto zc_fut1 = zc_prom1->get_future();
   auto zc_get1 =
      [zc_prom1](ReturnMessage<AsyncClient::TxResult> txObj)->void
   {
      auto&& tx = txObj.get();
      zc_prom1->set_value(move(tx));
   };

   bdvObj->getTxByHash(ZChash1, zc_get1);
   auto zc_obj1 = zc_fut1.get();
   EXPECT_EQ(ZChash1, zc_obj1->getThisHash());
   EXPECT_EQ(zc_obj1->getTxHeight(), UINT32_MAX);

   //grab both zc from async client
   auto zc_prom2 = make_shared<promise<AsyncClient::TxBatchResult>>();
   auto zc_fut2 = zc_prom2->get_future();
   auto zc_get2 =
      [zc_prom2](ReturnMessage<AsyncClient::TxBatchResult> txObj)->void
   {
      auto&& txVec = txObj.get();
      zc_prom2->set_value(move(txVec));
   };

   set<BinaryData> bothZC = { ZChash1, ZChash2 };
   bdvObj->getTxBatchByHash(bothZC, zc_get2);
   auto zc_obj2 = zc_fut2.get();

   ASSERT_EQ(zc_obj2.size(), 2);

   auto iterZc1 = zc_obj2.find(ZChash1);
   ASSERT_NE(iterZc1, zc_obj2.end());
   ASSERT_NE(iterZc1->second, nullptr);
   EXPECT_EQ(ZChash1, iterZc1->second->getThisHash());
   EXPECT_EQ(iterZc1->second->getTxHeight(), UINT32_MAX);

   auto iterZc2 = zc_obj2.find(ZChash2);
   ASSERT_NE(iterZc2, zc_obj2.end());
   ASSERT_NE(iterZc2->second, nullptr);
   EXPECT_EQ(ZChash2, iterZc2->second->getThisHash());
   EXPECT_EQ(iterZc2->second->getTxHeight(), UINT32_MAX);

   //push an extra block
   TestUtils::appendBlocks({ "2" }, blk0dat_);
   DBTestUtils::triggerNewBlockNotification(theBDMt_);
   pCallback->waitOnSignal(BDMAction_NewBlock);

   //get the new ledgers
   auto ledger3_prom =
      make_shared<promise<vector<DBClientClasses::LedgerEntry>>>();
   auto ledger3_fut = ledger3_prom->get_future();
   auto ledger3_get =
      [ledger3_prom](ReturnMessage<vector<DBClientClasses::LedgerEntry>> ledgerV)->void
   {
      ledger3_prom->set_value(move(ledgerV.get()));
   };
   main_delegate.getHistoryPage(0, ledger3_get);
   main_ledger = move(ledger3_fut.get());

   //check ledgers
   EXPECT_EQ(main_ledger.size(), 5);

   EXPECT_EQ(main_ledger[0].getValue(), -20 * COIN);
   EXPECT_EQ(main_ledger[0].getBlockNum(), 2);
   EXPECT_EQ(main_ledger[0].getIndex(), 2);

   EXPECT_EQ(main_ledger[1].getValue(), -25 * COIN);
   EXPECT_EQ(main_ledger[1].getBlockNum(), 2);
   EXPECT_EQ(main_ledger[1].getIndex(), 1);

   EXPECT_EQ(main_ledger[2].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[2].getBlockNum(), 2);
   EXPECT_EQ(main_ledger[2].getIndex(), 0);

   EXPECT_EQ(main_ledger[3].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[3].getBlockNum(), 1);
   EXPECT_EQ(main_ledger[3].getIndex(), 0);

   EXPECT_EQ(main_ledger[4].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[4].getBlockNum(), 0);
   EXPECT_EQ(main_ledger[4].getIndex(), 0);


   //grab ZC1 from async client
   auto zc_prom3 = make_shared<promise<AsyncClient::TxResult>>();
   auto zc_fut3 = zc_prom3->get_future();
   auto zc_get3 =
      [zc_prom3](ReturnMessage<AsyncClient::TxResult> txObj)->void
   {
      auto&& tx = txObj.get();
      zc_prom3->set_value(move(tx));
   };

   bdvObj->getTxByHash(ZChash1, zc_get3);
   auto zc_obj3 = zc_fut3.get();
   EXPECT_EQ(ZChash1, zc_obj3->getThisHash());
   EXPECT_EQ(zc_obj3->getTxHeight(), 2);

   //grab both zc from async client
   auto zc_prom4 = make_shared<promise<AsyncClient::TxBatchResult>>();
   auto zc_fut4 = zc_prom4->get_future();
   auto zc_get4 =
      [zc_prom4](ReturnMessage<AsyncClient::TxBatchResult> txObj)->void
   {
      auto&& txVec = txObj.get();
      zc_prom4->set_value(move(txVec));
   };

   bdvObj->getTxBatchByHash(bothZC, zc_get4);
   auto zc_obj4 = zc_fut4.get();

   ASSERT_EQ(zc_obj4.size(), 2);

   auto iterZc3 = zc_obj4.find(ZChash1);
   ASSERT_NE(iterZc3, zc_obj4.end());
   ASSERT_NE(iterZc3->second, nullptr);
   EXPECT_EQ(ZChash1, iterZc3->second->getThisHash());
   EXPECT_EQ(iterZc3->second->getTxHeight(), 2);

   auto iterZc4 = zc_obj4.find(ZChash2);
   ASSERT_NE(iterZc4, zc_obj4.end());
   ASSERT_NE(iterZc4->second, nullptr);
   EXPECT_EQ(ZChash2, iterZc4->second->getThisHash());
   EXPECT_EQ(iterZc4->second->getTxHeight(), 2);

   //disconnect
   bdvObj->unregisterFromDB();

   //cleanup
   auto&& bdvObj2 = AsyncClient::BlockDataViewer::getNewBDV(
      "127.0.0.1", NetworkSettings::listenPort(), ArmoryConfig::getDataDir(),
      authPeersPassLbd_, NetworkSettings::ephemeralPeers(), true, nullptr);
   bdvObj2->addPublicKey(serverPubkey);
   bdvObj2->connectToRemote();

   bdvObj2->shutdown(NetworkSettings::cookie());
   WebSocketServer::waitOnShutdown();

   EXPECT_EQ(theBDMt_->bdm()->zeroConfCont()->getMatcherMapSize(), 0);

   delete theBDMt_;
   theBDMt_ = nullptr;
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_Supernode_WebSocket, ZcUpdate_RPC)
{
   /*
   Some sigs in static test chain are borked. P2SH scripts are borked too. This
   test plucks transactions from the static chain to push as ZC. Skip sig checks
   on the unit test mock P2P node to avoid faililng the test.
   */
   nodePtr_->checkSigs(false);

   TestUtils::setBlocks({ "0", "1" }, blk0dat_);
   WebSocketServer::initAuthPeers(authPeersPassLbd_);
   WebSocketServer::start(theBDMt_, true);
   auto&& serverPubkey = WebSocketServer::getPublicKey();

   vector<BinaryData> scrAddrVec;
   scrAddrVec.push_back(TestChain::scrAddrA);
   scrAddrVec.push_back(TestChain::scrAddrB);
   scrAddrVec.push_back(TestChain::scrAddrC);

   theBDMt_->start(DBSettings::initMode());

   auto pCallback = make_shared<DBTestUtils::UTCallback>();
   auto bdvObj = AsyncClient::BlockDataViewer::getNewBDV(
      "127.0.0.1", NetworkSettings::listenPort(), 
      ArmoryConfig::getDataDir(),
      authPeersPassLbd_, 
      NetworkSettings::ephemeralPeers(), true, 
      pCallback);
   bdvObj->addPublicKey(serverPubkey);
   bdvObj->connectToRemote();
   bdvObj->registerWithDB(BitcoinSettings::getMagicBytes());

   //go online
   bdvObj->goOnline();
   pCallback->waitOnSignal(BDMAction_Ready);

   vector<string> walletRegIDs;

   auto&& wallet1 = bdvObj->instantiateWallet("wallet1");
   walletRegIDs.push_back(
      wallet1.registerAddresses(scrAddrVec, false));

   //wait on registration ack
   pCallback->waitOnManySignals(BDMAction_Refresh, walletRegIDs);

   //get wallets delegate
   auto del1_prom = make_shared<promise<AsyncClient::LedgerDelegate>>();
   auto del1_fut = del1_prom->get_future();
   auto del1_get = [del1_prom](
      ReturnMessage<AsyncClient::LedgerDelegate> delegate)->void
   {
      del1_prom->set_value(move(delegate.get()));
   };
   bdvObj->getLedgerDelegateForWallets(del1_get);
   auto&& main_delegate = del1_fut.get();

   auto ledger_prom =
      make_shared<promise<vector<DBClientClasses::LedgerEntry>>>();
   auto ledger_fut = ledger_prom->get_future();
   auto ledger_get =
      [ledger_prom](
         ReturnMessage<vector<DBClientClasses::LedgerEntry>> ledgerV)->void
   {
      ledger_prom->set_value(move(ledgerV.get()));
   };
   main_delegate.getHistoryPage(0, ledger_get);
   auto&& main_ledger = ledger_fut.get();

   //check ledgers
   EXPECT_EQ(main_ledger.size(), 2);

   EXPECT_EQ(main_ledger[0].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[0].getBlockNum(), 1);
   EXPECT_EQ(main_ledger[0].getIndex(), 0);

   EXPECT_EQ(main_ledger[1].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[1].getBlockNum(), 0);
   EXPECT_EQ(main_ledger[1].getIndex(), 0);

   //add the 2 zc
   auto&& ZC1 = TestUtils::getTx(2, 1); //block 2, tx 1
   auto&& ZChash1 = BtcUtils::getHash256(ZC1);

   auto&& ZC2 = TestUtils::getTx(2, 2); //block 2, tx 2
   auto&& ZChash2 = BtcUtils::getHash256(ZC2);

   auto broadcastId1 = bdvObj->broadcastThroughRPC(ZC1);
   auto broadcastId2 = bdvObj->broadcastThroughRPC(ZC2);
   
   {
      set<BinaryData> zcHashes = { ZChash1, ZChash2 };
      set<BinaryData> scrAddrSet1, scrAddrSet2;

      Tx zctx1(ZC1);
      for (unsigned i = 0; i < zctx1.getNumTxOut(); i++)
         scrAddrSet1.insert(zctx1.getScrAddrForTxOut(i));

      Tx zctx2(ZC2);
      for (unsigned i = 0; i < zctx2.getNumTxOut(); i++)
         scrAddrSet2.insert(zctx2.getScrAddrForTxOut(i));

      pCallback->waitOnZc({ZChash1}, scrAddrSet1, broadcastId1);
      pCallback->waitOnZc({ZChash2}, scrAddrSet2, broadcastId2);
   }

   //get the new ledgers
   auto ledger2_prom =
      make_shared<promise<vector<DBClientClasses::LedgerEntry>>>();
   auto ledger2_fut = ledger2_prom->get_future();
   auto ledger2_get =
      [ledger2_prom](ReturnMessage<vector<DBClientClasses::LedgerEntry>> ledgerV)->void
   {
      ledger2_prom->set_value(move(ledgerV.get()));
   };
   main_delegate.getHistoryPage(0, ledger2_get);
   main_ledger = move(ledger2_fut.get());

   //check ledgers
   EXPECT_EQ(main_ledger.size(), 4);

   EXPECT_EQ(main_ledger[0].getValue(), -20 * COIN);
   EXPECT_EQ(main_ledger[0].getBlockNum(), UINT32_MAX);
   EXPECT_EQ(main_ledger[0].getIndex(), 1);

   EXPECT_EQ(main_ledger[1].getValue(), -25 * COIN);
   EXPECT_EQ(main_ledger[1].getBlockNum(), UINT32_MAX);
   EXPECT_EQ(main_ledger[1].getIndex(), 0);

   EXPECT_EQ(main_ledger[2].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[2].getBlockNum(), 1);
   EXPECT_EQ(main_ledger[2].getIndex(), 0);

   EXPECT_EQ(main_ledger[3].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[3].getBlockNum(), 0);
   EXPECT_EQ(main_ledger[3].getIndex(), 0);

   /*tx cache coverage*/
   //grab ZC1 from async client
   auto zc_prom1 = make_shared<promise<AsyncClient::TxResult>>();
   auto zc_fut1 = zc_prom1->get_future();
   auto zc_get1 =
      [zc_prom1](ReturnMessage<AsyncClient::TxResult> txObj)->void
   {
      auto&& tx = txObj.get();
      zc_prom1->set_value(move(tx));
   };

   bdvObj->getTxByHash(ZChash1, zc_get1);
   auto zc_obj1 = zc_fut1.get();
   EXPECT_EQ(ZChash1, zc_obj1->getThisHash());
   EXPECT_EQ(zc_obj1->getTxHeight(), UINT32_MAX);

   //grab both zc from async client
   auto zc_prom2 = make_shared<promise<AsyncClient::TxBatchResult>>();
   auto zc_fut2 = zc_prom2->get_future();
   auto zc_get2 =
      [zc_prom2](ReturnMessage<AsyncClient::TxBatchResult> txObj)->void
   {
      auto&& txVec = txObj.get();
      zc_prom2->set_value(move(txVec));
   };

   set<BinaryData> bothZC = { ZChash1, ZChash2 };
   bdvObj->getTxBatchByHash(bothZC, zc_get2);
   auto zc_obj2 = zc_fut2.get();

   ASSERT_EQ(zc_obj2.size(), 2);
   
   auto iterZc1 = zc_obj2.find(ZChash1);
   ASSERT_NE(iterZc1, zc_obj2.end());
   ASSERT_NE(iterZc1->second, nullptr);
   EXPECT_EQ(ZChash1, iterZc1->second->getThisHash());
   EXPECT_EQ(iterZc1->second->getTxHeight(), UINT32_MAX);

   auto iterZc2 = zc_obj2.find(ZChash2);
   ASSERT_NE(iterZc2, zc_obj2.end());
   ASSERT_NE(iterZc2->second, nullptr);
   EXPECT_EQ(ZChash2, iterZc2->second->getThisHash());
   EXPECT_EQ(iterZc2->second->getTxHeight(), UINT32_MAX);

   //push an extra block
   TestUtils::appendBlocks({ "2" }, blk0dat_);
   DBTestUtils::triggerNewBlockNotification(theBDMt_);
   pCallback->waitOnSignal(BDMAction_NewBlock);

   //get the new ledgers
   auto ledger3_prom =
      make_shared<promise<vector<DBClientClasses::LedgerEntry>>>();
   auto ledger3_fut = ledger3_prom->get_future();
   auto ledger3_get =
      [ledger3_prom](ReturnMessage<vector<DBClientClasses::LedgerEntry>> ledgerV)->void
   {
      ledger3_prom->set_value(move(ledgerV.get()));
   };
   main_delegate.getHistoryPage(0, ledger3_get);
   main_ledger = move(ledger3_fut.get());

   //check ledgers
   EXPECT_EQ(main_ledger.size(), 5);

   EXPECT_EQ(main_ledger[0].getValue(), -20 * COIN);
   EXPECT_EQ(main_ledger[0].getBlockNum(), 2);
   EXPECT_EQ(main_ledger[0].getIndex(), 2);

   EXPECT_EQ(main_ledger[1].getValue(), -25 * COIN);
   EXPECT_EQ(main_ledger[1].getBlockNum(), 2);
   EXPECT_EQ(main_ledger[1].getIndex(), 1);

   EXPECT_EQ(main_ledger[2].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[2].getBlockNum(), 2);
   EXPECT_EQ(main_ledger[2].getIndex(), 0);

   EXPECT_EQ(main_ledger[3].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[3].getBlockNum(), 1);
   EXPECT_EQ(main_ledger[3].getIndex(), 0);

   EXPECT_EQ(main_ledger[4].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[4].getBlockNum(), 0);
   EXPECT_EQ(main_ledger[4].getIndex(), 0);


   //grab ZC1 from async client
   auto zc_prom3 = make_shared<promise<AsyncClient::TxResult>>();
   auto zc_fut3 = zc_prom3->get_future();
   auto zc_get3 =
      [zc_prom3](ReturnMessage<AsyncClient::TxResult> txObj)->void
   {
      auto&& tx = txObj.get();
      zc_prom3->set_value(move(tx));
   };

   bdvObj->getTxByHash(ZChash1, zc_get3);
   auto zc_obj3 = zc_fut3.get();
   EXPECT_EQ(ZChash1, zc_obj3->getThisHash());
   EXPECT_EQ(zc_obj3->getTxHeight(), 2);

   //grab both zc from async client
   auto zc_prom4 = make_shared<promise<AsyncClient::TxBatchResult>>();
   auto zc_fut4 = zc_prom4->get_future();
   auto zc_get4 =
      [zc_prom4](ReturnMessage<AsyncClient::TxBatchResult> txObj)->void
   {
      auto&& txVec = txObj.get();
      zc_prom4->set_value(move(txVec));
   };

   bdvObj->getTxBatchByHash(bothZC, zc_get4);
   auto zc_obj4 = zc_fut4.get();

   ASSERT_EQ(zc_obj4.size(), 2);
   auto iterZc3 = zc_obj4.find(ZChash1);
   ASSERT_NE(iterZc3, zc_obj4.end());
   ASSERT_NE(iterZc3->second, nullptr);
   EXPECT_EQ(ZChash1, iterZc3->second->getThisHash());
   EXPECT_EQ(iterZc3->second->getTxHeight(), 2);

   auto iterZc4 = zc_obj4.find(ZChash2);
   ASSERT_NE(iterZc4, zc_obj4.end());
   ASSERT_NE(iterZc4->second, nullptr);
   EXPECT_EQ(ZChash2, iterZc4->second->getThisHash());
   EXPECT_EQ(iterZc4->second->getTxHeight(), 2);

   //disconnect
   bdvObj->unregisterFromDB();

   //cleanup
   auto&& bdvObj2 = AsyncClient::BlockDataViewer::getNewBDV(
      "127.0.0.1", NetworkSettings::listenPort(), ArmoryConfig::getDataDir(),
      authPeersPassLbd_, NetworkSettings::ephemeralPeers(), true, nullptr);
   bdvObj2->addPublicKey(serverPubkey);
   bdvObj2->connectToRemote();

   bdvObj2->shutdown(NetworkSettings::cookie());
   WebSocketServer::waitOnShutdown();

   EXPECT_EQ(theBDMt_->bdm()->zeroConfCont()->getMatcherMapSize(), 0);

   delete theBDMt_;
   theBDMt_ = nullptr;
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_Supernode_WebSocket, ZcUpdate_RPC_Fallback)
{
   /*
   Some sigs in static test chain are borked. P2SH scripts are borked too. This
   test plucks transactions from the static chain to push as ZC. Skip sig checks
   on the unit test mock P2P node to avoid faililng the test.
   */
   nodePtr_->checkSigs(false);

   TestUtils::setBlocks({ "0", "1" }, blk0dat_);
   WebSocketServer::initAuthPeers(authPeersPassLbd_);
   WebSocketServer::start(theBDMt_, true);
   auto&& serverPubkey = WebSocketServer::getPublicKey();

   vector<BinaryData> scrAddrVec;
   scrAddrVec.push_back(TestChain::scrAddrA);
   scrAddrVec.push_back(TestChain::scrAddrB);
   scrAddrVec.push_back(TestChain::scrAddrC);

   theBDMt_->start(DBSettings::initMode());

   auto pCallback = make_shared<DBTestUtils::UTCallback>();
   auto bdvObj = AsyncClient::BlockDataViewer::getNewBDV(
      "127.0.0.1", NetworkSettings::listenPort(), 
      ArmoryConfig::getDataDir(),
      authPeersPassLbd_, 
      NetworkSettings::ephemeralPeers(), true, //public server
      pCallback);
   bdvObj->addPublicKey(serverPubkey);
   bdvObj->connectToRemote();
   bdvObj->registerWithDB(BitcoinSettings::getMagicBytes());

   //go online
   bdvObj->goOnline();
   pCallback->waitOnSignal(BDMAction_Ready);

   vector<string> walletRegIDs;

   auto&& wallet1 = bdvObj->instantiateWallet("wallet1");
   walletRegIDs.push_back(
      wallet1.registerAddresses(scrAddrVec, false));

   //wait on registration ack
   pCallback->waitOnManySignals(BDMAction_Refresh, walletRegIDs);

   //get wallets delegate
   auto del1_prom = make_shared<promise<AsyncClient::LedgerDelegate>>();
   auto del1_fut = del1_prom->get_future();
   auto del1_get = [del1_prom](
      ReturnMessage<AsyncClient::LedgerDelegate> delegate)->void
   {
      del1_prom->set_value(move(delegate.get()));
   };
   bdvObj->getLedgerDelegateForWallets(del1_get);
   auto&& main_delegate = del1_fut.get();

   auto ledger_prom =
      make_shared<promise<vector<DBClientClasses::LedgerEntry>>>();
   auto ledger_fut = ledger_prom->get_future();
   auto ledger_get =
      [ledger_prom](
         ReturnMessage<vector<DBClientClasses::LedgerEntry>> ledgerV)->void
   {
      ledger_prom->set_value(move(ledgerV.get()));
   };
   main_delegate.getHistoryPage(0, ledger_get);
   auto&& main_ledger = ledger_fut.get();

   //check ledgers
   EXPECT_EQ(main_ledger.size(), 2);

   EXPECT_EQ(main_ledger[0].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[0].getBlockNum(), 1);
   EXPECT_EQ(main_ledger[0].getIndex(), 0);

   EXPECT_EQ(main_ledger[1].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[1].getBlockNum(), 0);
   EXPECT_EQ(main_ledger[1].getIndex(), 0);

   //add the 2 zc
   auto&& ZC1 = TestUtils::getTx(2, 1); //block 2, tx 1
   auto&& ZChash1 = BtcUtils::getHash256(ZC1);

   auto&& ZC2 = TestUtils::getTx(2, 2); //block 2, tx 2
   auto&& ZChash2 = BtcUtils::getHash256(ZC2);

   //both these zc will be skipped by the p2p broadcast interface,
   //should trigger a RPC broadcast
   nodePtr_->skipZc(2);
   auto broadcastId1 = bdvObj->broadcastZC(ZC1);
   auto broadcastId2 = bdvObj->broadcastZC(ZC2);
   
   {
      set<BinaryData> scrAddrSet1, scrAddrSet2;

      Tx zctx1(ZC1);
      for (unsigned i = 0; i < zctx1.getNumTxOut(); i++)
         scrAddrSet1.insert(zctx1.getScrAddrForTxOut(i));

      Tx zctx2(ZC2);
      for (unsigned i = 0; i < zctx2.getNumTxOut(); i++)
         scrAddrSet2.insert(zctx2.getScrAddrForTxOut(i));

      pCallback->waitOnZc({ZChash1}, scrAddrSet1, broadcastId1);
      pCallback->waitOnZc({ZChash2}, scrAddrSet2, broadcastId2);
   }

   //get the new ledgers
   auto ledger2_prom =
      make_shared<promise<vector<DBClientClasses::LedgerEntry>>>();
   auto ledger2_fut = ledger2_prom->get_future();
   auto ledger2_get =
      [ledger2_prom](ReturnMessage<vector<DBClientClasses::LedgerEntry>> ledgerV)->void
   {
      ledger2_prom->set_value(move(ledgerV.get()));
   };
   main_delegate.getHistoryPage(0, ledger2_get);
   main_ledger = move(ledger2_fut.get());

   //check ledgers
   EXPECT_EQ(main_ledger.size(), 4);

   EXPECT_EQ(main_ledger[0].getValue(), -20 * COIN);
   EXPECT_EQ(main_ledger[0].getBlockNum(), UINT32_MAX);
   EXPECT_EQ(main_ledger[0].getIndex(), 3);

   EXPECT_EQ(main_ledger[1].getValue(), -25 * COIN);
   EXPECT_EQ(main_ledger[1].getBlockNum(), UINT32_MAX);
   EXPECT_EQ(main_ledger[1].getIndex(), 2);

   EXPECT_EQ(main_ledger[2].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[2].getBlockNum(), 1);
   EXPECT_EQ(main_ledger[2].getIndex(), 0);

   EXPECT_EQ(main_ledger[3].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[3].getBlockNum(), 0);
   EXPECT_EQ(main_ledger[3].getIndex(), 0);

   //tx cache testing
   //grab ZC1 from async client
   auto zc_prom1 = make_shared<promise<AsyncClient::TxResult>>();
   auto zc_fut1 = zc_prom1->get_future();
   auto zc_get1 =
      [zc_prom1](ReturnMessage<AsyncClient::TxResult> txObj)->void
   {
      auto&& tx = txObj.get();
      zc_prom1->set_value(move(tx));
   };

   bdvObj->getTxByHash(ZChash1, zc_get1);
   auto zc_obj1 = zc_fut1.get();
   EXPECT_EQ(ZChash1, zc_obj1->getThisHash());
   EXPECT_EQ(zc_obj1->getTxHeight(), UINT32_MAX);

   //grab both zc from async client
   auto zc_prom2 = make_shared<promise<AsyncClient::TxBatchResult>>();
   auto zc_fut2 = zc_prom2->get_future();
   auto zc_get2 =
      [zc_prom2](ReturnMessage<AsyncClient::TxBatchResult> txObj)->void
   {
      auto&& txVec = txObj.get();
      zc_prom2->set_value(move(txVec));
   };

   set<BinaryData> bothZC = { ZChash1, ZChash2 };
   bdvObj->getTxBatchByHash(bothZC, zc_get2);
   auto zc_obj2 = zc_fut2.get();

   ASSERT_EQ(zc_obj2.size(), 2);

   auto iterZc1 = zc_obj2.find(ZChash1);
   ASSERT_NE(iterZc1, zc_obj2.end());
   ASSERT_NE(iterZc1->second, nullptr);
   EXPECT_EQ(ZChash1, iterZc1->second->getThisHash());
   EXPECT_EQ(iterZc1->second->getTxHeight(), UINT32_MAX);

   auto iterZc2 = zc_obj2.find(ZChash2);
   ASSERT_NE(iterZc2, zc_obj2.end());
   ASSERT_NE(iterZc2->second, nullptr);
   EXPECT_EQ(ZChash2, iterZc2->second->getThisHash());
   EXPECT_EQ(iterZc2->second->getTxHeight(), UINT32_MAX);

   //push an extra block
   TestUtils::appendBlocks({ "2" }, blk0dat_);
   DBTestUtils::triggerNewBlockNotification(theBDMt_);
   pCallback->waitOnSignal(BDMAction_NewBlock);

   //get the new ledgers
   auto ledger3_prom =
      make_shared<promise<vector<DBClientClasses::LedgerEntry>>>();
   auto ledger3_fut = ledger3_prom->get_future();
   auto ledger3_get =
      [ledger3_prom](ReturnMessage<vector<DBClientClasses::LedgerEntry>> ledgerV)->void
   {
      ledger3_prom->set_value(move(ledgerV.get()));
   };
   main_delegate.getHistoryPage(0, ledger3_get);
   main_ledger = move(ledger3_fut.get());

   //check ledgers
   EXPECT_EQ(main_ledger.size(), 5);

   EXPECT_EQ(main_ledger[0].getValue(), -20 * COIN);
   EXPECT_EQ(main_ledger[0].getBlockNum(), 2);
   EXPECT_EQ(main_ledger[0].getIndex(), 2);

   EXPECT_EQ(main_ledger[1].getValue(), -25 * COIN);
   EXPECT_EQ(main_ledger[1].getBlockNum(), 2);
   EXPECT_EQ(main_ledger[1].getIndex(), 1);

   EXPECT_EQ(main_ledger[2].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[2].getBlockNum(), 2);
   EXPECT_EQ(main_ledger[2].getIndex(), 0);

   EXPECT_EQ(main_ledger[3].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[3].getBlockNum(), 1);
   EXPECT_EQ(main_ledger[3].getIndex(), 0);

   EXPECT_EQ(main_ledger[4].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[4].getBlockNum(), 0);
   EXPECT_EQ(main_ledger[4].getIndex(), 0);


   //grab ZC1 from async client
   auto zc_prom3 = make_shared<promise<AsyncClient::TxResult>>();
   auto zc_fut3 = zc_prom3->get_future();
   auto zc_get3 =
      [zc_prom3](ReturnMessage<AsyncClient::TxResult> txObj)->void
   {
      auto&& tx = txObj.get();
      zc_prom3->set_value(move(tx));
   };

   bdvObj->getTxByHash(ZChash1, zc_get3);
   auto zc_obj3 = zc_fut3.get();
   EXPECT_EQ(ZChash1, zc_obj3->getThisHash());
   EXPECT_EQ(zc_obj3->getTxHeight(), 2);

   //grab both zc from async client
   auto zc_prom4 = make_shared<promise<AsyncClient::TxBatchResult>>();
   auto zc_fut4 = zc_prom4->get_future();
   auto zc_get4 =
      [zc_prom4](ReturnMessage<AsyncClient::TxBatchResult> txObj)->void
   {
      auto&& txVec = txObj.get();
      zc_prom4->set_value(move(txVec));
   };

   bdvObj->getTxBatchByHash(bothZC, zc_get4);
   auto zc_obj4 = zc_fut4.get();

   ASSERT_EQ(zc_obj4.size(), 2);

   auto iterZc3 = zc_obj4.find(ZChash1);
   ASSERT_NE(iterZc3, zc_obj4.end());
   ASSERT_NE(iterZc3->second, nullptr);
   EXPECT_EQ(ZChash1, iterZc3->second->getThisHash());
   EXPECT_EQ(iterZc3->second->getTxHeight(), 2);

   auto iterZc4 = zc_obj4.find(ZChash2);
   ASSERT_NE(iterZc4, zc_obj4.end());
   ASSERT_NE(iterZc4->second, nullptr);
   EXPECT_EQ(ZChash2, iterZc4->second->getThisHash());
   EXPECT_EQ(iterZc4->second->getTxHeight(), 2);

   //disconnect
   bdvObj->unregisterFromDB();

   //cleanup
   auto&& bdvObj2 = AsyncClient::BlockDataViewer::getNewBDV(
      "127.0.0.1", NetworkSettings::listenPort(), ArmoryConfig::getDataDir(),
      authPeersPassLbd_, NetworkSettings::ephemeralPeers(), true, nullptr);
   bdvObj2->addPublicKey(serverPubkey);
   bdvObj2->connectToRemote();

   bdvObj2->shutdown(NetworkSettings::cookie());
   WebSocketServer::waitOnShutdown();

   EXPECT_EQ(theBDMt_->bdm()->zeroConfCont()->getMatcherMapSize(), 0);

   delete theBDMt_;
   theBDMt_ = nullptr;
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_Supernode_WebSocket, ZcUpdate_RPC_Fallback_SingleBatch)
{
   /*
   Some sigs in static test chain are borked. P2SH scripts are borked too. This
   test plucks transactions from the static chain to push as ZC. Skip sig checks
   on the unit test mock P2P node to avoid faililng the test.
   */
   nodePtr_->checkSigs(false);

   TestUtils::setBlocks({ "0", "1" }, blk0dat_);
   WebSocketServer::initAuthPeers(authPeersPassLbd_);
   WebSocketServer::start(theBDMt_, true);
   auto&& serverPubkey = WebSocketServer::getPublicKey();

   vector<BinaryData> scrAddrVec;
   scrAddrVec.push_back(TestChain::scrAddrA);
   scrAddrVec.push_back(TestChain::scrAddrB);
   scrAddrVec.push_back(TestChain::scrAddrC);

   theBDMt_->start(DBSettings::initMode());

   auto pCallback = make_shared<DBTestUtils::UTCallback>();
   auto bdvObj = AsyncClient::BlockDataViewer::getNewBDV(
      "127.0.0.1", NetworkSettings::listenPort(), 
      ArmoryConfig::getDataDir(),
      authPeersPassLbd_, 
      NetworkSettings::ephemeralPeers(), true, //public server
      pCallback);
   bdvObj->addPublicKey(serverPubkey);
   bdvObj->connectToRemote();
   bdvObj->registerWithDB(BitcoinSettings::getMagicBytes());

   //go online
   bdvObj->goOnline();
   pCallback->waitOnSignal(BDMAction_Ready);

   vector<string> walletRegIDs;

   auto&& wallet1 = bdvObj->instantiateWallet("wallet1");
   walletRegIDs.push_back(
      wallet1.registerAddresses(scrAddrVec, false));

   //wait on registration ack
   pCallback->waitOnManySignals(BDMAction_Refresh, walletRegIDs);

   //get wallets delegate
   auto del1_prom = make_shared<promise<AsyncClient::LedgerDelegate>>();
   auto del1_fut = del1_prom->get_future();
   auto del1_get = [del1_prom](
      ReturnMessage<AsyncClient::LedgerDelegate> delegate)->void
   {
      del1_prom->set_value(move(delegate.get()));
   };
   bdvObj->getLedgerDelegateForWallets(del1_get);
   auto&& main_delegate = del1_fut.get();

   auto ledger_prom =
      make_shared<promise<vector<DBClientClasses::LedgerEntry>>>();
   auto ledger_fut = ledger_prom->get_future();
   auto ledger_get =
      [ledger_prom](
         ReturnMessage<vector<DBClientClasses::LedgerEntry>> ledgerV)->void
   {
      ledger_prom->set_value(move(ledgerV.get()));
   };
   main_delegate.getHistoryPage(0, ledger_get);
   auto&& main_ledger = ledger_fut.get();

   //check ledgers
   EXPECT_EQ(main_ledger.size(), 2);

   EXPECT_EQ(main_ledger[0].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[0].getBlockNum(), 1);
   EXPECT_EQ(main_ledger[0].getIndex(), 0);

   EXPECT_EQ(main_ledger[1].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[1].getBlockNum(), 0);
   EXPECT_EQ(main_ledger[1].getIndex(), 0);

   //add the 2 zc
   auto&& ZC1 = TestUtils::getTx(2, 1); //block 2, tx 1
   auto&& ZChash1 = BtcUtils::getHash256(ZC1);

   auto&& ZC2 = TestUtils::getTx(2, 2); //block 2, tx 2
   auto&& ZChash2 = BtcUtils::getHash256(ZC2);

   //both these zc will be skipped by the p2p broadcast interface,
   //should trigger a RPC broadcast
   nodePtr_->skipZc(2);
   vector<BinaryData> zcVec = {ZC1, ZC2};
   auto broadcastId1 = bdvObj->broadcastZC(zcVec);
   
   {
      set<BinaryData> zcHashes = { ZChash1, ZChash2 };
      set<BinaryData> scrAddrSet;

      Tx zctx1(ZC1);
      for (unsigned i = 0; i < zctx1.getNumTxOut(); i++)
         scrAddrSet.insert(zctx1.getScrAddrForTxOut(i));

      Tx zctx2(ZC2);
      for (unsigned i = 0; i < zctx2.getNumTxOut(); i++)
         scrAddrSet.insert(zctx2.getScrAddrForTxOut(i));

      pCallback->waitOnZc(zcHashes, scrAddrSet, broadcastId1);
   }

   //get the new ledgers
   auto ledger2_prom =
      make_shared<promise<vector<DBClientClasses::LedgerEntry>>>();
   auto ledger2_fut = ledger2_prom->get_future();
   auto ledger2_get =
      [ledger2_prom](ReturnMessage<vector<DBClientClasses::LedgerEntry>> ledgerV)->void
   {
      ledger2_prom->set_value(move(ledgerV.get()));
   };
   main_delegate.getHistoryPage(0, ledger2_get);
   main_ledger = move(ledger2_fut.get());

   //check ledgers
   EXPECT_EQ(main_ledger.size(), 4);

   EXPECT_EQ(main_ledger[0].getValue(), -20 * COIN);
   EXPECT_EQ(main_ledger[0].getBlockNum(), UINT32_MAX);
   EXPECT_EQ(main_ledger[0].getIndex(), 3);

   EXPECT_EQ(main_ledger[1].getValue(), -25 * COIN);
   EXPECT_EQ(main_ledger[1].getBlockNum(), UINT32_MAX);
   EXPECT_EQ(main_ledger[1].getIndex(), 2);

   EXPECT_EQ(main_ledger[2].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[2].getBlockNum(), 1);
   EXPECT_EQ(main_ledger[2].getIndex(), 0);

   EXPECT_EQ(main_ledger[3].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[3].getBlockNum(), 0);
   EXPECT_EQ(main_ledger[3].getIndex(), 0);

   //tx cache testing
   //grab ZC1 from async client
   auto zc_prom1 = make_shared<promise<AsyncClient::TxResult>>();
   auto zc_fut1 = zc_prom1->get_future();
   auto zc_get1 =
      [zc_prom1](ReturnMessage<AsyncClient::TxResult> txObj)->void
   {
      auto&& tx = txObj.get();
      zc_prom1->set_value(move(tx));
   };

   bdvObj->getTxByHash(ZChash1, zc_get1);
   auto zc_obj1 = zc_fut1.get();
   EXPECT_EQ(ZChash1, zc_obj1->getThisHash());
   EXPECT_EQ(zc_obj1->getTxHeight(), UINT32_MAX);

   //grab both zc from async client
   auto zc_prom2 = make_shared<promise<AsyncClient::TxBatchResult>>();
   auto zc_fut2 = zc_prom2->get_future();
   auto zc_get2 =
      [zc_prom2](ReturnMessage<AsyncClient::TxBatchResult> txObj)->void
   {
      auto&& txVec = txObj.get();
      zc_prom2->set_value(move(txVec));
   };

   set<BinaryData> bothZC = { ZChash1, ZChash2 };
   bdvObj->getTxBatchByHash(bothZC, zc_get2);
   auto zc_obj2 = zc_fut2.get();

   ASSERT_EQ(zc_obj2.size(), 2);

   auto iterZc1 = zc_obj2.find(ZChash1);
   ASSERT_NE(iterZc1, zc_obj2.end());
   ASSERT_NE(iterZc1->second, nullptr);
   EXPECT_EQ(ZChash1, iterZc1->second->getThisHash());
   EXPECT_EQ(iterZc1->second->getTxHeight(), UINT32_MAX);

   auto iterZc2 = zc_obj2.find(ZChash2);
   ASSERT_NE(iterZc2, zc_obj2.end());
   ASSERT_NE(iterZc2->second, nullptr);
   EXPECT_EQ(ZChash2, iterZc2->second->getThisHash());
   EXPECT_EQ(iterZc2->second->getTxHeight(), UINT32_MAX);

   //push an extra block
   TestUtils::appendBlocks({ "2" }, blk0dat_);
   DBTestUtils::triggerNewBlockNotification(theBDMt_);
   pCallback->waitOnSignal(BDMAction_NewBlock);

   //get the new ledgers
   auto ledger3_prom =
      make_shared<promise<vector<DBClientClasses::LedgerEntry>>>();
   auto ledger3_fut = ledger3_prom->get_future();
   auto ledger3_get =
      [ledger3_prom](ReturnMessage<vector<DBClientClasses::LedgerEntry>> ledgerV)->void
   {
      ledger3_prom->set_value(move(ledgerV.get()));
   };
   main_delegate.getHistoryPage(0, ledger3_get);
   main_ledger = move(ledger3_fut.get());

   //check ledgers
   EXPECT_EQ(main_ledger.size(), 5);

   EXPECT_EQ(main_ledger[0].getValue(), -20 * COIN);
   EXPECT_EQ(main_ledger[0].getBlockNum(), 2);
   EXPECT_EQ(main_ledger[0].getIndex(), 2);

   EXPECT_EQ(main_ledger[1].getValue(), -25 * COIN);
   EXPECT_EQ(main_ledger[1].getBlockNum(), 2);
   EXPECT_EQ(main_ledger[1].getIndex(), 1);

   EXPECT_EQ(main_ledger[2].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[2].getBlockNum(), 2);
   EXPECT_EQ(main_ledger[2].getIndex(), 0);

   EXPECT_EQ(main_ledger[3].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[3].getBlockNum(), 1);
   EXPECT_EQ(main_ledger[3].getIndex(), 0);

   EXPECT_EQ(main_ledger[4].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[4].getBlockNum(), 0);
   EXPECT_EQ(main_ledger[4].getIndex(), 0);


   //grab ZC1 from async client
   auto zc_prom3 = make_shared<promise<AsyncClient::TxResult>>();
   auto zc_fut3 = zc_prom3->get_future();
   auto zc_get3 =
      [zc_prom3](ReturnMessage<AsyncClient::TxResult> txObj)->void
   {
      auto&& tx = txObj.get();
      zc_prom3->set_value(move(tx));
   };

   bdvObj->getTxByHash(ZChash1, zc_get3);
   auto zc_obj3 = zc_fut3.get();
   EXPECT_EQ(ZChash1, zc_obj3->getThisHash());
   EXPECT_EQ(zc_obj3->getTxHeight(), 2);

   //grab both zc from async client
   auto zc_prom4 = make_shared<promise<AsyncClient::TxBatchResult>>();
   auto zc_fut4 = zc_prom4->get_future();
   auto zc_get4 =
      [zc_prom4](ReturnMessage<AsyncClient::TxBatchResult> txObj)->void
   {
      auto&& txVec = txObj.get();
      zc_prom4->set_value(move(txVec));
   };

   bdvObj->getTxBatchByHash(bothZC, zc_get4);
   auto zc_obj4 = zc_fut4.get();

   ASSERT_EQ(zc_obj4.size(), 2);

   auto iterZc3 = zc_obj4.find(ZChash1);
   ASSERT_NE(iterZc3, zc_obj4.end());
   ASSERT_NE(iterZc3->second, nullptr);
   EXPECT_EQ(ZChash1, iterZc3->second->getThisHash());
   EXPECT_EQ(iterZc3->second->getTxHeight(), 2);

   auto iterZc4 = zc_obj4.find(ZChash2);
   ASSERT_NE(iterZc4, zc_obj4.end());
   ASSERT_NE(iterZc4->second, nullptr);
   EXPECT_EQ(ZChash2, iterZc4->second->getThisHash());
   EXPECT_EQ(iterZc4->second->getTxHeight(), 2);

   //disconnect
   bdvObj->unregisterFromDB();

   //cleanup
   auto&& bdvObj2 = AsyncClient::BlockDataViewer::getNewBDV(
      "127.0.0.1", NetworkSettings::listenPort(), ArmoryConfig::getDataDir(),
      authPeersPassLbd_, NetworkSettings::ephemeralPeers(), true, nullptr);
   bdvObj2->addPublicKey(serverPubkey);
   bdvObj2->connectToRemote();

   bdvObj2->shutdown(NetworkSettings::cookie());
   WebSocketServer::waitOnShutdown();

   EXPECT_EQ(theBDMt_->bdm()->zeroConfCont()->getMatcherMapSize(), 0);

   delete theBDMt_;
   theBDMt_ = nullptr;
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_Supernode_WebSocket, ZcUpdate_AlreadyInMempool)
{
   /*
   Some sigs in static test chain are borked. P2SH scripts are borked too. This
   test plucks transactions from the static chain to push as ZC. Skip sig checks
   on the unit test mock P2P node to avoid faililng the test.
   */
   nodePtr_->checkSigs(false);

   TestUtils::setBlocks({ "0", "1" }, blk0dat_);
   WebSocketServer::initAuthPeers(authPeersPassLbd_);
   WebSocketServer::start(theBDMt_, true);
   auto&& serverPubkey = WebSocketServer::getPublicKey();

   vector<BinaryData> scrAddrVec;
   scrAddrVec.push_back(TestChain::scrAddrA);
   scrAddrVec.push_back(TestChain::scrAddrB);
   scrAddrVec.push_back(TestChain::scrAddrC);

   theBDMt_->start(DBSettings::initMode());

   auto pCallback = make_shared<DBTestUtils::UTCallback>();
   auto bdvObj = AsyncClient::BlockDataViewer::getNewBDV(
      "127.0.0.1", NetworkSettings::listenPort(), 
      ArmoryConfig::getDataDir(),
      authPeersPassLbd_, 
      NetworkSettings::ephemeralPeers(), true, //public server
      pCallback);
   bdvObj->addPublicKey(serverPubkey);
   bdvObj->connectToRemote();
   bdvObj->registerWithDB(BitcoinSettings::getMagicBytes());

   //go online
   bdvObj->goOnline();
   pCallback->waitOnSignal(BDMAction_Ready);

   vector<string> walletRegIDs;

   auto&& wallet1 = bdvObj->instantiateWallet("wallet1");
   walletRegIDs.push_back(
      wallet1.registerAddresses(scrAddrVec, false));

   //wait on registration ack
   pCallback->waitOnManySignals(BDMAction_Refresh, walletRegIDs);

   //get wallets delegate
   auto del1_prom = make_shared<promise<AsyncClient::LedgerDelegate>>();
   auto del1_fut = del1_prom->get_future();
   auto del1_get = [del1_prom](
      ReturnMessage<AsyncClient::LedgerDelegate> delegate)->void
   {
      del1_prom->set_value(move(delegate.get()));
   };
   bdvObj->getLedgerDelegateForWallets(del1_get);
   auto&& main_delegate = del1_fut.get();

   auto ledger_prom =
      make_shared<promise<vector<DBClientClasses::LedgerEntry>>>();
   auto ledger_fut = ledger_prom->get_future();
   auto ledger_get =
      [ledger_prom](
         ReturnMessage<vector<DBClientClasses::LedgerEntry>> ledgerV)->void
   {
      ledger_prom->set_value(move(ledgerV.get()));
   };
   main_delegate.getHistoryPage(0, ledger_get);
   auto&& main_ledger = ledger_fut.get();

   //check ledgers
   EXPECT_EQ(main_ledger.size(), 2);

   EXPECT_EQ(main_ledger[0].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[0].getBlockNum(), 1);
   EXPECT_EQ(main_ledger[0].getIndex(), 0);

   EXPECT_EQ(main_ledger[1].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[1].getBlockNum(), 0);
   EXPECT_EQ(main_ledger[1].getIndex(), 0);

   //add the 2 zc
   auto&& ZC1 = TestUtils::getTx(2, 1); //block 2, tx 1
   auto&& ZChash1 = BtcUtils::getHash256(ZC1);

   auto&& ZC2 = TestUtils::getTx(2, 2); //block 2, tx 2
   auto&& ZChash2 = BtcUtils::getHash256(ZC2);

   //pushZC
   auto broadcastId1 = bdvObj->broadcastZC(ZC1);
   auto broadcastId2 = bdvObj->broadcastZC(ZC2);
   
   {
      set<BinaryData> scrAddrSet1, scrAddrSet2;

      Tx zctx1(ZC1);
      for (unsigned i = 0; i < zctx1.getNumTxOut(); i++)
         scrAddrSet1.insert(zctx1.getScrAddrForTxOut(i));

      Tx zctx2(ZC2);
      for (unsigned i = 0; i < zctx2.getNumTxOut(); i++)
         scrAddrSet2.insert(zctx2.getScrAddrForTxOut(i));

      pCallback->waitOnZc({ZChash1}, scrAddrSet1, broadcastId1);
      pCallback->waitOnZc({ZChash2}, scrAddrSet2, broadcastId2);
   }

   //push them again, should get already in mempool error
   auto broadcastId3 = bdvObj->broadcastZC(ZC1);
   auto broadcastId4 = bdvObj->broadcastZC(ZC2);

   pCallback->waitOnError(
      ZChash1, ArmoryErrorCodes::ZcBroadcast_AlreadyInMempool, broadcastId3);
   pCallback->waitOnError(
      ZChash2, ArmoryErrorCodes::ZcBroadcast_AlreadyInMempool, broadcastId4);

   //get the new ledgers
   auto ledger2_prom =
      make_shared<promise<vector<DBClientClasses::LedgerEntry>>>();
   auto ledger2_fut = ledger2_prom->get_future();
   auto ledger2_get =
      [ledger2_prom](ReturnMessage<vector<DBClientClasses::LedgerEntry>> ledgerV)->void
   {
      ledger2_prom->set_value(move(ledgerV.get()));
   };
   main_delegate.getHistoryPage(0, ledger2_get);
   main_ledger = move(ledger2_fut.get());

   //check ledgers
   EXPECT_EQ(main_ledger.size(), 4);

   EXPECT_EQ(main_ledger[0].getValue(), -20 * COIN);
   EXPECT_EQ(main_ledger[0].getBlockNum(), UINT32_MAX);
   EXPECT_EQ(main_ledger[0].getIndex(), 1);

   EXPECT_EQ(main_ledger[1].getValue(), -25 * COIN);
   EXPECT_EQ(main_ledger[1].getBlockNum(), UINT32_MAX);
   EXPECT_EQ(main_ledger[1].getIndex(), 0);

   EXPECT_EQ(main_ledger[2].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[2].getBlockNum(), 1);
   EXPECT_EQ(main_ledger[2].getIndex(), 0);

   EXPECT_EQ(main_ledger[3].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[3].getBlockNum(), 0);
   EXPECT_EQ(main_ledger[3].getIndex(), 0);

   //tx cache testing
   //grab ZC1 from async client
   auto zc_prom1 = make_shared<promise<AsyncClient::TxResult>>();
   auto zc_fut1 = zc_prom1->get_future();
   auto zc_get1 =
      [zc_prom1](ReturnMessage<AsyncClient::TxResult> txObj)->void
   {
      auto&& tx = txObj.get();
      zc_prom1->set_value(move(tx));
   };

   bdvObj->getTxByHash(ZChash1, zc_get1);
   auto zc_obj1 = zc_fut1.get();
   EXPECT_EQ(ZChash1, zc_obj1->getThisHash());
   EXPECT_EQ(zc_obj1->getTxHeight(), UINT32_MAX);

   //grab both zc from async client
   auto zc_prom2 = make_shared<promise<AsyncClient::TxBatchResult>>();
   auto zc_fut2 = zc_prom2->get_future();
   auto zc_get2 =
      [zc_prom2](ReturnMessage<AsyncClient::TxBatchResult> txObj)->void
   {
      auto&& txVec = txObj.get();
      zc_prom2->set_value(move(txVec));
   };

   set<BinaryData> bothZC = { ZChash1, ZChash2 };
   bdvObj->getTxBatchByHash(bothZC, zc_get2);
   auto zc_obj2 = zc_fut2.get();

   ASSERT_EQ(zc_obj2.size(), 2);

   auto iterZc1 = zc_obj2.find(ZChash1);
   ASSERT_NE(iterZc1, zc_obj2.end());
   ASSERT_NE(iterZc1->second, nullptr);
   EXPECT_EQ(ZChash1, iterZc1->second->getThisHash());
   EXPECT_EQ(iterZc1->second->getTxHeight(), UINT32_MAX);

   auto iterZc2 = zc_obj2.find(ZChash2);
   ASSERT_NE(iterZc2, zc_obj2.end());
   ASSERT_NE(iterZc2->second, nullptr);
   EXPECT_EQ(ZChash2, iterZc2->second->getThisHash());
   EXPECT_EQ(iterZc2->second->getTxHeight(), UINT32_MAX);

   //push an extra block
   TestUtils::appendBlocks({ "2" }, blk0dat_);
   DBTestUtils::triggerNewBlockNotification(theBDMt_);
   pCallback->waitOnSignal(BDMAction_NewBlock);

   //get the new ledgers
   auto ledger3_prom =
      make_shared<promise<vector<DBClientClasses::LedgerEntry>>>();
   auto ledger3_fut = ledger3_prom->get_future();
   auto ledger3_get =
      [ledger3_prom](ReturnMessage<vector<DBClientClasses::LedgerEntry>> ledgerV)->void
   {
      ledger3_prom->set_value(move(ledgerV.get()));
   };
   main_delegate.getHistoryPage(0, ledger3_get);
   main_ledger = move(ledger3_fut.get());

   //check ledgers
   EXPECT_EQ(main_ledger.size(), 5);

   EXPECT_EQ(main_ledger[0].getValue(), -20 * COIN);
   EXPECT_EQ(main_ledger[0].getBlockNum(), 2);
   EXPECT_EQ(main_ledger[0].getIndex(), 2);

   EXPECT_EQ(main_ledger[1].getValue(), -25 * COIN);
   EXPECT_EQ(main_ledger[1].getBlockNum(), 2);
   EXPECT_EQ(main_ledger[1].getIndex(), 1);

   EXPECT_EQ(main_ledger[2].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[2].getBlockNum(), 2);
   EXPECT_EQ(main_ledger[2].getIndex(), 0);

   EXPECT_EQ(main_ledger[3].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[3].getBlockNum(), 1);
   EXPECT_EQ(main_ledger[3].getIndex(), 0);

   EXPECT_EQ(main_ledger[4].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[4].getBlockNum(), 0);
   EXPECT_EQ(main_ledger[4].getIndex(), 0);


   //grab ZC1 from async client
   auto zc_prom3 = make_shared<promise<AsyncClient::TxResult>>();
   auto zc_fut3 = zc_prom3->get_future();
   auto zc_get3 =
      [zc_prom3](ReturnMessage<AsyncClient::TxResult> txObj)->void
   {
      auto&& tx = txObj.get();
      zc_prom3->set_value(move(tx));
   };

   bdvObj->getTxByHash(ZChash1, zc_get3);
   auto zc_obj3 = zc_fut3.get();
   EXPECT_EQ(ZChash1, zc_obj3->getThisHash());
   EXPECT_EQ(zc_obj3->getTxHeight(), 2);

   //grab both zc from async client
   auto zc_prom4 = make_shared<promise<AsyncClient::TxBatchResult>>();
   auto zc_fut4 = zc_prom4->get_future();
   auto zc_get4 =
      [zc_prom4](ReturnMessage<AsyncClient::TxBatchResult> txObj)->void
   {
      auto&& txVec = txObj.get();
      zc_prom4->set_value(move(txVec));
   };

   bdvObj->getTxBatchByHash(bothZC, zc_get4);
   auto zc_obj4 = zc_fut4.get();

   ASSERT_EQ(zc_obj4.size(), 2);

   auto iterZc3 = zc_obj4.find(ZChash1);
   ASSERT_NE(iterZc3, zc_obj4.end());
   ASSERT_NE(iterZc3->second, nullptr);
   EXPECT_EQ(ZChash1, iterZc3->second->getThisHash());
   EXPECT_EQ(iterZc3->second->getTxHeight(), 2);

   auto iterZc4 = zc_obj4.find(ZChash2);
   ASSERT_NE(iterZc4, zc_obj4.end());
   ASSERT_NE(iterZc4->second, nullptr);
   EXPECT_EQ(ZChash2, iterZc4->second->getThisHash());
   EXPECT_EQ(iterZc4->second->getTxHeight(), 2);

   //disconnect
   bdvObj->unregisterFromDB();

   //cleanup
   auto&& bdvObj2 = AsyncClient::BlockDataViewer::getNewBDV(
      "127.0.0.1", NetworkSettings::listenPort(), ArmoryConfig::getDataDir(),
      authPeersPassLbd_, NetworkSettings::ephemeralPeers(), true, nullptr);
   bdvObj2->addPublicKey(serverPubkey);
   bdvObj2->connectToRemote();

   bdvObj2->shutdown(NetworkSettings::cookie());
   WebSocketServer::waitOnShutdown();

   EXPECT_EQ(theBDMt_->bdm()->zeroConfCont()->getMatcherMapSize(), 0);

   delete theBDMt_;
   theBDMt_ = nullptr;
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_Supernode_WebSocket, ZcUpdate_AlreadyInMempool_Batched)
{
   /*
   Some sigs in static test chain are borked. P2SH scripts are borked too. This
   test plucks transactions from the static chain to push as ZC. Skip sig checks
   on the unit test mock P2P node to avoid faililng the test.
   */
   nodePtr_->checkSigs(false);

   TestUtils::setBlocks({ "0", "1" }, blk0dat_);
   WebSocketServer::initAuthPeers(authPeersPassLbd_);
   WebSocketServer::start(theBDMt_, true);
   auto&& serverPubkey = WebSocketServer::getPublicKey();

   vector<BinaryData> scrAddrVec;
   scrAddrVec.push_back(TestChain::scrAddrA);
   scrAddrVec.push_back(TestChain::scrAddrB);
   scrAddrVec.push_back(TestChain::scrAddrC);

   theBDMt_->start(DBSettings::initMode());

   auto pCallback = make_shared<DBTestUtils::UTCallback>();
   auto bdvObj = AsyncClient::BlockDataViewer::getNewBDV(
      "127.0.0.1", NetworkSettings::listenPort(), 
      ArmoryConfig::getDataDir(),
      authPeersPassLbd_, 
      NetworkSettings::ephemeralPeers(), true, //public server
      pCallback);
   bdvObj->addPublicKey(serverPubkey);
   bdvObj->connectToRemote();
   bdvObj->registerWithDB(BitcoinSettings::getMagicBytes());

   //go online
   bdvObj->goOnline();
   pCallback->waitOnSignal(BDMAction_Ready);

   vector<string> walletRegIDs;

   auto&& wallet1 = bdvObj->instantiateWallet("wallet1");
   walletRegIDs.push_back(
      wallet1.registerAddresses(scrAddrVec, false));

   //wait on registration ack
   pCallback->waitOnManySignals(BDMAction_Refresh, walletRegIDs);

   //get wallets delegate
   auto del1_prom = make_shared<promise<AsyncClient::LedgerDelegate>>();
   auto del1_fut = del1_prom->get_future();
   auto del1_get = [del1_prom](
      ReturnMessage<AsyncClient::LedgerDelegate> delegate)->void
   {
      del1_prom->set_value(move(delegate.get()));
   };
   bdvObj->getLedgerDelegateForWallets(del1_get);
   auto&& main_delegate = del1_fut.get();

   auto ledger_prom =
      make_shared<promise<vector<DBClientClasses::LedgerEntry>>>();
   auto ledger_fut = ledger_prom->get_future();
   auto ledger_get =
      [ledger_prom](
         ReturnMessage<vector<DBClientClasses::LedgerEntry>> ledgerV)->void
   {
      ledger_prom->set_value(move(ledgerV.get()));
   };
   main_delegate.getHistoryPage(0, ledger_get);
   auto&& main_ledger = ledger_fut.get();

   //check ledgers
   EXPECT_EQ(main_ledger.size(), 2);

   EXPECT_EQ(main_ledger[0].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[0].getBlockNum(), 1);
   EXPECT_EQ(main_ledger[0].getIndex(), 0);

   EXPECT_EQ(main_ledger[1].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[1].getBlockNum(), 0);
   EXPECT_EQ(main_ledger[1].getIndex(), 0);

   //add the 2 zc
   auto&& ZC1 = TestUtils::getTx(2, 1); //block 2, tx 1
   auto&& ZChash1 = BtcUtils::getHash256(ZC1);

   auto&& ZC2 = TestUtils::getTx(2, 2); //block 2, tx 2
   auto&& ZChash2 = BtcUtils::getHash256(ZC2);

   //push the first zc
   auto broadcastId1 = bdvObj->broadcastZC(ZC1);
   
   {
      set<BinaryData> zcHashes = { ZChash1 };
      set<BinaryData> scrAddrSet;

      Tx zctx1(ZC1);
      for (unsigned i = 0; i < zctx1.getNumTxOut(); i++)
         scrAddrSet.insert(zctx1.getScrAddrForTxOut(i));

      pCallback->waitOnZc(zcHashes, scrAddrSet, broadcastId1);
   }

   //push them again, should get already in mempool error for first zc, notif for 2nd
   auto broadcastId2 = bdvObj->broadcastZC( { ZC1, ZC2 } );
   pCallback->waitOnError(
      ZChash1, ArmoryErrorCodes::ZcBroadcast_AlreadyInMempool, broadcastId2);

   {
      set<BinaryData> zcHashes = { ZChash2 };
      set<BinaryData> scrAddrSet;

      Tx zctx2(ZC2);
      for (unsigned i = 0; i < zctx2.getNumTxOut(); i++)
         scrAddrSet.insert(zctx2.getScrAddrForTxOut(i));

      pCallback->waitOnZc(zcHashes, scrAddrSet, broadcastId2);
   }

   //get the new ledgers
   auto ledger2_prom =
      make_shared<promise<vector<DBClientClasses::LedgerEntry>>>();
   auto ledger2_fut = ledger2_prom->get_future();
   auto ledger2_get =
      [ledger2_prom](ReturnMessage<vector<DBClientClasses::LedgerEntry>> ledgerV)->void
   {
      ledger2_prom->set_value(move(ledgerV.get()));
   };
   main_delegate.getHistoryPage(0, ledger2_get);
   main_ledger = move(ledger2_fut.get());

   //check ledgers
   EXPECT_EQ(main_ledger.size(), 4);

   EXPECT_EQ(main_ledger[0].getValue(), -20 * COIN);
   EXPECT_EQ(main_ledger[0].getBlockNum(), UINT32_MAX);
   //zc index is 2 since 0 and 1 were assigned to the first zc: 0 at
   //the solo broadcast, 1 at the batched broadcast, which had the first
   //zc fail as already-in-mempool
   EXPECT_EQ(main_ledger[0].getIndex(), 2); 

   EXPECT_EQ(main_ledger[1].getValue(), -25 * COIN);
   EXPECT_EQ(main_ledger[1].getBlockNum(), UINT32_MAX);
   EXPECT_EQ(main_ledger[1].getIndex(), 0);

   EXPECT_EQ(main_ledger[2].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[2].getBlockNum(), 1);
   EXPECT_EQ(main_ledger[2].getIndex(), 0);

   EXPECT_EQ(main_ledger[3].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[3].getBlockNum(), 0);
   EXPECT_EQ(main_ledger[3].getIndex(), 0);

   //tx cache testing
   //grab ZC1 from async client
   auto zc_prom1 = make_shared<promise<AsyncClient::TxResult>>();
   auto zc_fut1 = zc_prom1->get_future();
   auto zc_get1 =
      [zc_prom1](ReturnMessage<AsyncClient::TxResult> txObj)->void
   {
      auto&& tx = txObj.get();
      zc_prom1->set_value(move(tx));
   };

   bdvObj->getTxByHash(ZChash1, zc_get1);
   auto zc_obj1 = zc_fut1.get();
   EXPECT_EQ(ZChash1, zc_obj1->getThisHash());
   EXPECT_EQ(zc_obj1->getTxHeight(), UINT32_MAX);

   //grab both zc from async client
   auto zc_prom2 = make_shared<promise<AsyncClient::TxBatchResult>>();
   auto zc_fut2 = zc_prom2->get_future();
   auto zc_get2 =
      [zc_prom2](ReturnMessage<AsyncClient::TxBatchResult> txObj)->void
   {
      auto&& txVec = txObj.get();
      zc_prom2->set_value(move(txVec));
   };

   set<BinaryData> bothZC = { ZChash1, ZChash2 };
   bdvObj->getTxBatchByHash(bothZC, zc_get2);
   auto zc_obj2 = zc_fut2.get();

   ASSERT_EQ(zc_obj2.size(), 2);

   auto iterZc1 = zc_obj2.find(ZChash1);
   ASSERT_NE(iterZc1, zc_obj2.end());
   ASSERT_NE(iterZc1->second, nullptr);
   EXPECT_EQ(ZChash1, iterZc1->second->getThisHash());
   EXPECT_EQ(iterZc1->second->getTxHeight(), UINT32_MAX);

   auto iterZc2 = zc_obj2.find(ZChash2);
   ASSERT_NE(iterZc2, zc_obj2.end());
   ASSERT_NE(iterZc2->second, nullptr);
   EXPECT_EQ(ZChash2, iterZc2->second->getThisHash());
   EXPECT_EQ(iterZc2->second->getTxHeight(), UINT32_MAX);
   
   //push an extra block
   TestUtils::appendBlocks({ "2" }, blk0dat_);
   DBTestUtils::triggerNewBlockNotification(theBDMt_);
   pCallback->waitOnSignal(BDMAction_NewBlock);

   //get the new ledgers
   auto ledger3_prom =
      make_shared<promise<vector<DBClientClasses::LedgerEntry>>>();
   auto ledger3_fut = ledger3_prom->get_future();
   auto ledger3_get =
      [ledger3_prom](ReturnMessage<vector<DBClientClasses::LedgerEntry>> ledgerV)->void
   {
      ledger3_prom->set_value(move(ledgerV.get()));
   };
   main_delegate.getHistoryPage(0, ledger3_get);
   main_ledger = move(ledger3_fut.get());

   //check ledgers
   EXPECT_EQ(main_ledger.size(), 5);

   EXPECT_EQ(main_ledger[0].getValue(), -20 * COIN);
   EXPECT_EQ(main_ledger[0].getBlockNum(), 2);
   EXPECT_EQ(main_ledger[0].getIndex(), 2);

   EXPECT_EQ(main_ledger[1].getValue(), -25 * COIN);
   EXPECT_EQ(main_ledger[1].getBlockNum(), 2);
   EXPECT_EQ(main_ledger[1].getIndex(), 1);

   EXPECT_EQ(main_ledger[2].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[2].getBlockNum(), 2);
   EXPECT_EQ(main_ledger[2].getIndex(), 0);

   EXPECT_EQ(main_ledger[3].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[3].getBlockNum(), 1);
   EXPECT_EQ(main_ledger[3].getIndex(), 0);

   EXPECT_EQ(main_ledger[4].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[4].getBlockNum(), 0);
   EXPECT_EQ(main_ledger[4].getIndex(), 0);


   //grab ZC1 from async client
   auto zc_prom3 = make_shared<promise<AsyncClient::TxResult>>();
   auto zc_fut3 = zc_prom3->get_future();
   auto zc_get3 =
      [zc_prom3](ReturnMessage<AsyncClient::TxResult> txObj)->void
   {
      auto&& tx = txObj.get();
      zc_prom3->set_value(move(tx));
   };

   bdvObj->getTxByHash(ZChash1, zc_get3);
   auto zc_obj3 = zc_fut3.get();
   EXPECT_EQ(ZChash1, zc_obj3->getThisHash());
   EXPECT_EQ(zc_obj3->getTxHeight(), 2);

   //grab both zc from async client
   auto zc_prom4 = make_shared<promise<AsyncClient::TxBatchResult>>();
   auto zc_fut4 = zc_prom4->get_future();
   auto zc_get4 =
      [zc_prom4](ReturnMessage<AsyncClient::TxBatchResult> txObj)->void
   {
      auto&& txVec = txObj.get();
      zc_prom4->set_value(move(txVec));
   };

   bdvObj->getTxBatchByHash(bothZC, zc_get4);
   auto zc_obj4 = zc_fut4.get();

   ASSERT_EQ(zc_obj4.size(), 2);

   auto iterZc3 = zc_obj4.find(ZChash1);
   ASSERT_NE(iterZc3, zc_obj4.end());
   ASSERT_NE(iterZc3->second, nullptr);
   EXPECT_EQ(ZChash1, iterZc3->second->getThisHash());
   EXPECT_EQ(iterZc3->second->getTxHeight(), 2);

   auto iterZc4 = zc_obj4.find(ZChash2);
   ASSERT_NE(iterZc4, zc_obj4.end());
   ASSERT_NE(iterZc4->second, nullptr);
   EXPECT_EQ(ZChash2, iterZc4->second->getThisHash());
   EXPECT_EQ(iterZc4->second->getTxHeight(), 2);

   //disconnect
   bdvObj->unregisterFromDB();

   //cleanup
   auto&& bdvObj2 = AsyncClient::BlockDataViewer::getNewBDV(
      "127.0.0.1", NetworkSettings::listenPort(), ArmoryConfig::getDataDir(),
      authPeersPassLbd_, NetworkSettings::ephemeralPeers(), true, nullptr);
   bdvObj2->addPublicKey(serverPubkey);
   bdvObj2->connectToRemote();

   bdvObj2->shutdown(NetworkSettings::cookie());
   WebSocketServer::waitOnShutdown();

   EXPECT_EQ(theBDMt_->bdm()->zeroConfCont()->getMatcherMapSize(), 0);

   delete theBDMt_;
   theBDMt_ = nullptr;
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_Supernode_WebSocket, ZcUpdate_AlreadyInNodeMempool)
{
   /*
   Some sigs in static test chain are borked. P2SH scripts are borked too. This
   test plucks transactions from the static chain to push as ZC. Skip sig checks
   on the unit test mock P2P node to avoid faililng the test.
   */
   nodePtr_->checkSigs(false);

   //grab the first zc
   auto&& ZC1 = TestUtils::getTx(2, 1); //block 2, tx 1
   auto&& ZChash1 = BtcUtils::getHash256(ZC1);

   {
      //feed to node mempool while the zc parser is down
      DBTestUtils::ZcVector zcVec;
      zcVec.push_back(ZC1, 0);
      DBTestUtils::pushNewZc(theBDMt_, zcVec, 0);
   }

   startupBIP150CTX(4);

   TestUtils::setBlocks({ "0", "1" }, blk0dat_);
   WebSocketServer::initAuthPeers(authPeersPassLbd_);
   WebSocketServer::start(theBDMt_, true);
   auto&& serverPubkey = WebSocketServer::getPublicKey();

   vector<BinaryData> scrAddrVec;
   scrAddrVec.push_back(TestChain::scrAddrA);
   scrAddrVec.push_back(TestChain::scrAddrB);
   scrAddrVec.push_back(TestChain::scrAddrC);

   theBDMt_->start(DBSettings::initMode());

   auto pCallback = make_shared<DBTestUtils::UTCallback>();
   auto bdvObj = AsyncClient::BlockDataViewer::getNewBDV(
      "127.0.0.1", NetworkSettings::listenPort(), 
      ArmoryConfig::getDataDir(),
      authPeersPassLbd_, 
      NetworkSettings::ephemeralPeers(), true, //public server
      pCallback);
   bdvObj->addPublicKey(serverPubkey);
   bdvObj->connectToRemote();
   bdvObj->registerWithDB(BitcoinSettings::getMagicBytes());

   //go online
   bdvObj->goOnline();
   pCallback->waitOnSignal(BDMAction_Ready);

   vector<string> walletRegIDs;

   auto&& wallet1 = bdvObj->instantiateWallet("wallet1");
   walletRegIDs.push_back(
      wallet1.registerAddresses(scrAddrVec, false));

   //wait on registration ack
   pCallback->waitOnManySignals(BDMAction_Refresh, walletRegIDs);

   //get wallets delegate
   auto del1_prom = make_shared<promise<AsyncClient::LedgerDelegate>>();
   auto del1_fut = del1_prom->get_future();
   auto del1_get = [del1_prom](
      ReturnMessage<AsyncClient::LedgerDelegate> delegate)->void
   {
      del1_prom->set_value(move(delegate.get()));
   };
   bdvObj->getLedgerDelegateForWallets(del1_get);
   auto&& main_delegate = del1_fut.get();

   auto ledger_prom =
      make_shared<promise<vector<DBClientClasses::LedgerEntry>>>();
   auto ledger_fut = ledger_prom->get_future();
   auto ledger_get =
      [ledger_prom](
         ReturnMessage<vector<DBClientClasses::LedgerEntry>> ledgerV)->void
   {
      ledger_prom->set_value(move(ledgerV.get()));
   };
   main_delegate.getHistoryPage(0, ledger_get);
   auto&& main_ledger = ledger_fut.get();

   //check ledgers
   EXPECT_EQ(main_ledger.size(), 2);

   EXPECT_EQ(main_ledger[0].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[0].getBlockNum(), 1);
   EXPECT_EQ(main_ledger[0].getIndex(), 0);

   EXPECT_EQ(main_ledger[1].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[1].getBlockNum(), 0);
   EXPECT_EQ(main_ledger[1].getIndex(), 0);

   //add the 2 zc

   auto&& ZC2 = TestUtils::getTx(2, 2); //block 2, tx 2
   auto&& ZChash2 = BtcUtils::getHash256(ZC2);

   vector<BinaryData> zcVec = {ZC1, ZC2};
   auto broadcastId1 = bdvObj->broadcastZC(zcVec);
   
   {
      set<BinaryData> zcHashes = { ZChash1, ZChash2 };
      set<BinaryData> scrAddrSet;

      Tx zctx1(ZC1);
      for (unsigned i = 0; i < zctx1.getNumTxOut(); i++)
         scrAddrSet.insert(zctx1.getScrAddrForTxOut(i));

      Tx zctx2(ZC2);
      for (unsigned i = 0; i < zctx2.getNumTxOut(); i++)
         scrAddrSet.insert(zctx2.getScrAddrForTxOut(i));

      pCallback->waitOnZc(zcHashes, scrAddrSet, broadcastId1);
   }

   //get the new ledgers
   auto ledger2_prom =
      make_shared<promise<vector<DBClientClasses::LedgerEntry>>>();
   auto ledger2_fut = ledger2_prom->get_future();
   auto ledger2_get =
      [ledger2_prom](ReturnMessage<vector<DBClientClasses::LedgerEntry>> ledgerV)->void
   {
      ledger2_prom->set_value(move(ledgerV.get()));
   };
   main_delegate.getHistoryPage(0, ledger2_get);
   main_ledger = move(ledger2_fut.get());

   //check ledgers
   EXPECT_EQ(main_ledger.size(), 4);

   EXPECT_EQ(main_ledger[0].getValue(), -20 * COIN);
   EXPECT_EQ(main_ledger[0].getBlockNum(), UINT32_MAX);
   EXPECT_EQ(main_ledger[0].getIndex(), 3);

   EXPECT_EQ(main_ledger[1].getValue(), -25 * COIN);
   EXPECT_EQ(main_ledger[1].getBlockNum(), UINT32_MAX);
   EXPECT_EQ(main_ledger[1].getIndex(), 2);

   EXPECT_EQ(main_ledger[2].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[2].getBlockNum(), 1);
   EXPECT_EQ(main_ledger[2].getIndex(), 0);

   EXPECT_EQ(main_ledger[3].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[3].getBlockNum(), 0);
   EXPECT_EQ(main_ledger[3].getIndex(), 0);

   //tx cache testing
   //grab ZC1 from async client
   auto zc_prom1 = make_shared<promise<AsyncClient::TxResult>>();
   auto zc_fut1 = zc_prom1->get_future();
   auto zc_get1 =
      [zc_prom1](ReturnMessage<AsyncClient::TxResult> txObj)->void
   {
      auto&& tx = txObj.get();
      zc_prom1->set_value(move(tx));
   };

   bdvObj->getTxByHash(ZChash1, zc_get1);
   auto zc_obj1 = zc_fut1.get();
   EXPECT_EQ(ZChash1, zc_obj1->getThisHash());
   EXPECT_EQ(zc_obj1->getTxHeight(), UINT32_MAX);

   //grab both zc from async client
   auto zc_prom2 = make_shared<promise<AsyncClient::TxBatchResult>>();
   auto zc_fut2 = zc_prom2->get_future();
   auto zc_get2 =
      [zc_prom2](ReturnMessage<AsyncClient::TxBatchResult> txObj)->void
   {
      auto&& txVec = txObj.get();
      zc_prom2->set_value(move(txVec));
   };

   set<BinaryData> bothZC = { ZChash1, ZChash2 };
   bdvObj->getTxBatchByHash(bothZC, zc_get2);
   auto zc_obj2 = zc_fut2.get();

   ASSERT_EQ(zc_obj2.size(), 2);

   auto iterZc1 = zc_obj2.find(ZChash1);
   ASSERT_NE(iterZc1, zc_obj2.end());
   ASSERT_NE(iterZc1->second, nullptr);
   EXPECT_EQ(ZChash1, iterZc1->second->getThisHash());
   EXPECT_EQ(iterZc1->second->getTxHeight(), UINT32_MAX);

   auto iterZc2 = zc_obj2.find(ZChash2);
   ASSERT_NE(iterZc2, zc_obj2.end());
   ASSERT_NE(iterZc2->second, nullptr);
   EXPECT_EQ(ZChash2, iterZc2->second->getThisHash());
   EXPECT_EQ(iterZc2->second->getTxHeight(), UINT32_MAX);

   //push an extra block
   TestUtils::appendBlocks({ "2" }, blk0dat_);
   DBTestUtils::triggerNewBlockNotification(theBDMt_);
   pCallback->waitOnSignal(BDMAction_NewBlock);

   //get the new ledgers
   auto ledger3_prom =
      make_shared<promise<vector<DBClientClasses::LedgerEntry>>>();
   auto ledger3_fut = ledger3_prom->get_future();
   auto ledger3_get =
      [ledger3_prom](ReturnMessage<vector<DBClientClasses::LedgerEntry>> ledgerV)->void
   {
      ledger3_prom->set_value(move(ledgerV.get()));
   };
   main_delegate.getHistoryPage(0, ledger3_get);
   main_ledger = move(ledger3_fut.get());

   //check ledgers
   EXPECT_EQ(main_ledger.size(), 5);

   EXPECT_EQ(main_ledger[0].getValue(), -20 * COIN);
   EXPECT_EQ(main_ledger[0].getBlockNum(), 2);
   EXPECT_EQ(main_ledger[0].getIndex(), 2);

   EXPECT_EQ(main_ledger[1].getValue(), -25 * COIN);
   EXPECT_EQ(main_ledger[1].getBlockNum(), 2);
   EXPECT_EQ(main_ledger[1].getIndex(), 1);

   EXPECT_EQ(main_ledger[2].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[2].getBlockNum(), 2);
   EXPECT_EQ(main_ledger[2].getIndex(), 0);

   EXPECT_EQ(main_ledger[3].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[3].getBlockNum(), 1);
   EXPECT_EQ(main_ledger[3].getIndex(), 0);

   EXPECT_EQ(main_ledger[4].getValue(), 50 * COIN);
   EXPECT_EQ(main_ledger[4].getBlockNum(), 0);
   EXPECT_EQ(main_ledger[4].getIndex(), 0);


   //grab ZC1 from async client
   auto zc_prom3 = make_shared<promise<AsyncClient::TxResult>>();
   auto zc_fut3 = zc_prom3->get_future();
   auto zc_get3 =
      [zc_prom3](ReturnMessage<AsyncClient::TxResult> txObj)->void
   {
      auto&& tx = txObj.get();
      zc_prom3->set_value(move(tx));
   };

   bdvObj->getTxByHash(ZChash1, zc_get3);
   auto zc_obj3 = zc_fut3.get();
   EXPECT_EQ(ZChash1, zc_obj3->getThisHash());
   EXPECT_EQ(zc_obj3->getTxHeight(), 2);

   //grab both zc from async client
   auto zc_prom4 = make_shared<promise<AsyncClient::TxBatchResult>>();
   auto zc_fut4 = zc_prom4->get_future();
   auto zc_get4 =
      [zc_prom4](ReturnMessage<AsyncClient::TxBatchResult> txObj)->void
   {
      auto&& txVec = txObj.get();
      zc_prom4->set_value(move(txVec));
   };

   bdvObj->getTxBatchByHash(bothZC, zc_get4);
   auto zc_obj4 = zc_fut4.get();

   ASSERT_EQ(zc_obj4.size(), 2);

   auto iterZc3 = zc_obj4.find(ZChash1);
   ASSERT_NE(iterZc3, zc_obj4.end());
   ASSERT_NE(iterZc3->second, nullptr);
   EXPECT_EQ(ZChash1, iterZc3->second->getThisHash());
   EXPECT_EQ(iterZc3->second->getTxHeight(), 2);

   auto iterZc4 = zc_obj4.find(ZChash2);
   ASSERT_NE(iterZc4, zc_obj4.end());
   ASSERT_NE(iterZc4->second, nullptr);
   EXPECT_EQ(ZChash2, iterZc4->second->getThisHash());
   EXPECT_EQ(iterZc4->second->getTxHeight(), 2);

   //disconnect
   bdvObj->unregisterFromDB();

   //cleanup
   auto&& bdvObj2 = AsyncClient::BlockDataViewer::getNewBDV(
      "127.0.0.1", NetworkSettings::listenPort(), ArmoryConfig::getDataDir(),
      authPeersPassLbd_, NetworkSettings::ephemeralPeers(), true, nullptr);
   bdvObj2->addPublicKey(serverPubkey);
   bdvObj2->connectToRemote();

   bdvObj2->shutdown(NetworkSettings::cookie());
   WebSocketServer::waitOnShutdown();

   EXPECT_EQ(theBDMt_->bdm()->zeroConfCont()->getMatcherMapSize(), 0);

   delete theBDMt_;
   theBDMt_ = nullptr;
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_Supernode_WebSocket, ZcUpdate_RBFLowFee)
{
   //instantiate resolver feed overloaded object
   auto feed = make_shared<ResolverUtils::TestResolverFeed>();
   feed->addPrivKey(TestChain::privKeyAddrB);
   feed->addPrivKey(TestChain::privKeyAddrC);
   feed->addPrivKey(TestChain::privKeyAddrD);
   feed->addPrivKey(TestChain::privKeyAddrE);
   feed->addPrivKey(TestChain::privKeyAddrF);

   startupBIP150CTX(4);

   WebSocketServer::initAuthPeers(authPeersPassLbd_);
   WebSocketServer::start(theBDMt_, true);
   auto&& serverPubkey = WebSocketServer::getPublicKey();

   vector<BinaryData> scrAddrVec;
   scrAddrVec.push_back(TestChain::scrAddrA);
   scrAddrVec.push_back(TestChain::scrAddrB);
   scrAddrVec.push_back(TestChain::scrAddrC);
   scrAddrVec.push_back(TestChain::scrAddrD);
   scrAddrVec.push_back(TestChain::scrAddrE);
   scrAddrVec.push_back(TestChain::scrAddrF);

   theBDMt_->start(DBSettings::initMode());

   auto pCallback = make_shared<DBTestUtils::UTCallback>();
   auto bdvObj = AsyncClient::BlockDataViewer::getNewBDV(
      "127.0.0.1", NetworkSettings::listenPort(), 
      ArmoryConfig::getDataDir(),
      authPeersPassLbd_, 
      NetworkSettings::ephemeralPeers(), true, //public server
      pCallback);
   bdvObj->addPublicKey(serverPubkey);
   bdvObj->connectToRemote();
   bdvObj->registerWithDB(BitcoinSettings::getMagicBytes());

   auto&& wallet1 = bdvObj->instantiateWallet("wallet1");
   vector<string> walletRegIDs;
   walletRegIDs.push_back(
      wallet1.registerAddresses(scrAddrVec, false));

   //wait on registration ack
   pCallback->waitOnManySignals(BDMAction_Refresh, walletRegIDs);

   //go online
   bdvObj->goOnline();
   pCallback->waitOnSignal(BDMAction_Ready);

   //create tx from utxo lambda
   auto makeTxFromUtxo = [feed](const UTXO& utxo, const BinaryData& recipient)->BinaryData
   {
      auto spender = make_shared<ScriptSpender>(utxo);
      spender->setSequence(0xFFFFFFFF - 2); //flag rbf

      auto recPtr = make_shared<Recipient_P2PKH>(
         recipient.getSliceCopy(1, 20), utxo.getValue());

      Signer signer;
      signer.setFeed(feed);
      signer.addSpender(spender);
      signer.addRecipient(recPtr);

      signer.sign();
      return signer.serializeSignedTx();
   };

   //grab utxo from db
   auto getUtxo = [bdvObj](const BinaryData& addr)->vector<UTXO>
   {
      auto promPtr = make_shared<promise<vector<UTXO>>>();
      auto fut = promPtr->get_future();
      auto getUtxoLbd = [promPtr](ReturnMessage<vector<UTXO>> batch)->void
      {
         promPtr->set_value(batch.get());
      };

      bdvObj->getUTXOsForAddress(addr, false, getUtxoLbd);
      return fut.get();
   };

   //create tx from spender address lambda
   auto makeTx = [makeTxFromUtxo, getUtxo, bdvObj](
      const BinaryData& payer, const BinaryData& recipient)->BinaryData
   {
      auto utxoVec = getUtxo(payer);
      if (utxoVec.size() == 0)
         throw runtime_error("unexpected utxo vec size");

      auto& utxo = utxoVec[0];
      return makeTxFromUtxo(utxo, recipient);
   };

   //grab utxo from raw tx lambda
   auto getUtxoFromRawTx = [](BinaryData& rawTx, unsigned id)->UTXO
   {
      Tx tx(rawTx);
      if (id > tx.getNumTxOut())
         throw runtime_error("invalid txout count");

      auto&& txOut = tx.getTxOutCopy(id);
      
      UTXO utxo;
      utxo.unserializeRaw(txOut.serialize());
      utxo.txOutIndex_ = id;
      utxo.txHash_ = tx.getThisHash();

      return utxo;
   };

   vector<string> walletIDs;
   walletIDs.push_back(wallet1.walletID());

   //grab combined balances lambda
   auto getBalances = [bdvObj, walletIDs](void)->CombinedBalances
   {
      auto promPtr = make_shared<promise<map<string, CombinedBalances>>>();
      auto fut = promPtr->get_future();
      auto balLbd = [promPtr](
         ReturnMessage<map<string, CombinedBalances>> combBal)->void
      {
         promPtr->set_value(combBal.get());
      };

      bdvObj->getCombinedBalances(walletIDs, balLbd);
      auto&& balMap = fut.get();

      if (balMap.size() != 1)
         throw runtime_error("unexpected balance map size");

      return balMap.begin()->second;
   };

   //check original balances
   {
      auto&& combineBalances = getBalances();
      EXPECT_EQ(combineBalances.addressBalances_.size(), 6);

      auto iterA = combineBalances.addressBalances_.find(TestChain::scrAddrA);
      ASSERT_NE(iterA, combineBalances.addressBalances_.end());
      ASSERT_EQ(iterA->second.size(), 3);
      EXPECT_EQ(iterA->second[0], 50 * COIN);

      auto iterB = combineBalances.addressBalances_.find(TestChain::scrAddrB);
      ASSERT_NE(iterB, combineBalances.addressBalances_.end());
      ASSERT_EQ(iterB->second.size(), 3);
      EXPECT_EQ(iterB->second[0], 70 * COIN);

      auto iterC = combineBalances.addressBalances_.find(TestChain::scrAddrC);
      ASSERT_NE(iterC, combineBalances.addressBalances_.end());
      ASSERT_EQ(iterC->second.size(), 3);
      EXPECT_EQ(iterC->second[0], 20 * COIN);

      auto iterD = combineBalances.addressBalances_.find(TestChain::scrAddrD);
      ASSERT_NE(iterD, combineBalances.addressBalances_.end());
      ASSERT_EQ(iterD->second.size(), 3);
      EXPECT_EQ(iterD->second[0], 65 * COIN);

      auto iterE = combineBalances.addressBalances_.find(TestChain::scrAddrE);
      ASSERT_NE(iterE, combineBalances.addressBalances_.end());
      ASSERT_EQ(iterE->second.size(), 3);
      EXPECT_EQ(iterE->second[0], 30 * COIN);

      auto iterF = combineBalances.addressBalances_.find(TestChain::scrAddrF);
      ASSERT_NE(iterF, combineBalances.addressBalances_.end());
      ASSERT_EQ(iterF->second.size(), 3);
      EXPECT_EQ(iterF->second[0], 5 * COIN);
   }

   BinaryData branchPointBlockHash, mainBranchBlockHash;
   {
      auto top = theBDMt_->bdm()->blockchain()->top();
      branchPointBlockHash = top->getThisHash();
   }

   BinaryData bd_BtoC;
   UTXO utxoF;
   {
      //tx from B to C
      bd_BtoC = makeTx(TestChain::scrAddrB, TestChain::scrAddrC);

      //tx from F to A
      auto&& utxoVec = getUtxo(TestChain::scrAddrF);
      ASSERT_EQ(utxoVec.size(), 1);
      utxoF = utxoVec[0];
      auto bd_FtoD = makeTxFromUtxo(utxoF, TestChain::scrAddrA);

      //broadcast
      auto broadcastId1 = bdvObj->broadcastZC(bd_BtoC);
      auto broadcastId2 = bdvObj->broadcastZC(bd_FtoD);

      set<BinaryData> scrAddrSet1, scrAddrSet2;
      
      {
         Tx tx1(bd_BtoC);
         
         Tx tx2(bd_FtoD);
         
         scrAddrSet1.insert(TestChain::scrAddrB);
         scrAddrSet1.insert(TestChain::scrAddrC);

         scrAddrSet2.insert(TestChain::scrAddrF);
         scrAddrSet2.insert(TestChain::scrAddrA);

         pCallback->waitOnZc({tx1.getThisHash()}, scrAddrSet1, broadcastId1);
         pCallback->waitOnZc({tx2.getThisHash()}, scrAddrSet2, broadcastId2);
      }

      //tx from B to A, should fail with RBF low fee
      auto bd_BtoA = makeTx(TestChain::scrAddrB, TestChain::scrAddrA);
      Tx tx(bd_BtoA);

      auto broadcastId3 = bdvObj->broadcastZC(bd_BtoA);
      pCallback->waitOnError(tx.getThisHash(), 
         ArmoryErrorCodes::P2PReject_InsufficientFee, broadcastId3);
 
      //mine
      DBTestUtils::mineNewBlock(theBDMt_, TestChain::addrA, 1);
      pCallback->waitOnSignal(BDMAction_NewBlock);

      //zc C to E
      auto&& utxo = getUtxoFromRawTx(bd_BtoC, 0);
      auto bd_CtoE = makeTxFromUtxo(utxo, TestChain::scrAddrE);
      
      //broadcast
      bdvObj->broadcastZC(bd_CtoE);
      pCallback->waitOnSignal(BDMAction_ZC);

      //mine
      DBTestUtils::mineNewBlock(theBDMt_, TestChain::addrA, 1);
      pCallback->waitOnSignal(BDMAction_NewBlock);

      //check balances
      auto&& combineBalances = getBalances();

      /*
      D doesn't change so there should only be 5 balance entries
      C value does not change but the address sees a ZC in and a
      ZC out so the internal value change tracker counter was 
      incremented, resulting in an entry.
      */
      EXPECT_EQ(combineBalances.addressBalances_.size(), 5);

      auto iterA = combineBalances.addressBalances_.find(TestChain::scrAddrA);
      ASSERT_NE(iterA, combineBalances.addressBalances_.end());
      ASSERT_EQ(iterA->second.size(), 3);
      EXPECT_EQ(iterA->second[0], 155 * COIN);

      auto iterB = combineBalances.addressBalances_.find(TestChain::scrAddrB);
      ASSERT_NE(iterB, combineBalances.addressBalances_.end());
      ASSERT_EQ(iterB->second.size(), 3);
      EXPECT_EQ(iterB->second[0], 20 * COIN);

      auto iterC = combineBalances.addressBalances_.find(TestChain::scrAddrC);
      ASSERT_NE(iterC, combineBalances.addressBalances_.end());
      ASSERT_EQ(iterC->second.size(), 3);
      EXPECT_EQ(iterC->second[0], 20 * COIN);

      auto iterE = combineBalances.addressBalances_.find(TestChain::scrAddrE);
      ASSERT_NE(iterE, combineBalances.addressBalances_.end());
      ASSERT_EQ(iterE->second.size(), 3);
      EXPECT_EQ(iterE->second[0], 80 * COIN);

      auto iterF = combineBalances.addressBalances_.find(TestChain::scrAddrF);
      ASSERT_NE(iterF, combineBalances.addressBalances_.end());
      ASSERT_EQ(iterF->second.size(), 3);
      EXPECT_EQ(iterF->second[0], 0 * COIN);
   }

   //cleanup
   bdvObj->unregisterFromDB();

   //cleanup
   auto&& bdvObj2 = AsyncClient::BlockDataViewer::getNewBDV(
      "127.0.0.1", NetworkSettings::listenPort(), ArmoryConfig::getDataDir(),
      authPeersPassLbd_, NetworkSettings::ephemeralPeers(), true, nullptr);
   bdvObj2->addPublicKey(serverPubkey);
   bdvObj2->connectToRemote();

   bdvObj2->shutdown(NetworkSettings::cookie());
   WebSocketServer::waitOnShutdown();

   EXPECT_EQ(theBDMt_->bdm()->zeroConfCont()->getMatcherMapSize(), 0);

   delete theBDMt_;
   theBDMt_ = nullptr;   
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_Supernode_WebSocket, BatchZcChain)
{
   TestUtils::setBlocks({ "0", "1", "2", "3", "4", "5" }, blk0dat_);
   WebSocketServer::initAuthPeers(authPeersPassLbd_);
   WebSocketServer::start(theBDMt_, true);
   auto&& serverPubkey = WebSocketServer::getPublicKey();
   theBDMt_->start(DBSettings::initMode());

   {
      auto pCallback = make_shared<DBTestUtils::UTCallback>();
      auto&& bdvObj = AsyncClient::BlockDataViewer::getNewBDV(
         "127.0.0.1", NetworkSettings::listenPort(), 
         ArmoryConfig::getDataDir(),
         authPeersPassLbd_, 
         NetworkSettings::ephemeralPeers(), true,  //public server
         pCallback);
      bdvObj->addPublicKey(serverPubkey);
      bdvObj->connectToRemote();
      bdvObj->registerWithDB(BitcoinSettings::getMagicBytes());

      auto&& wallet1 = bdvObj->instantiateWallet("wallet1");

      vector<BinaryData> _scrAddrVec1;
      _scrAddrVec1.push_back(TestChain::scrAddrA);
      _scrAddrVec1.push_back(TestChain::scrAddrB);
      _scrAddrVec1.push_back(TestChain::scrAddrC);
      _scrAddrVec1.push_back(TestChain::scrAddrD);
      _scrAddrVec1.push_back(TestChain::scrAddrE);
      _scrAddrVec1.push_back(TestChain::scrAddrF);

      vector<string> walletRegIDs;
      walletRegIDs.push_back(
         wallet1.registerAddresses(_scrAddrVec1, false));

      //wait on registration ack
      pCallback->waitOnManySignals(BDMAction_Refresh, walletRegIDs);

      //go online
      bdvObj->goOnline();
      pCallback->waitOnSignal(BDMAction_Ready);

      //balance fetching routine
      vector<string> walletIDs = { wallet1.walletID() };
      auto getBalances = [bdvObj, walletIDs](void)->CombinedBalances
      {
         auto promPtr = make_shared<promise<map<string, CombinedBalances>>>();
         auto fut = promPtr->get_future();
         auto balLbd = [promPtr](
            ReturnMessage<map<string, CombinedBalances>> combBal)->void
         {
            promPtr->set_value(combBal.get());
         };

         bdvObj->getCombinedBalances(walletIDs, balLbd);
         auto&& balMap = fut.get();

         if (balMap.size() != 1)
            throw runtime_error("unexpected balance map size");

         return balMap.begin()->second;
      };

      //check balances before pushing zc
      auto&& combineBalances = getBalances();
      EXPECT_EQ(combineBalances.addressBalances_.size(), 6);

      {
         auto iterA = combineBalances.addressBalances_.find(TestChain::scrAddrA);
         ASSERT_NE(iterA, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterA->second.size(), 3);
         EXPECT_EQ(iterA->second[0], 50 * COIN);

         auto iterB = combineBalances.addressBalances_.find(TestChain::scrAddrB);
         ASSERT_NE(iterB, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterB->second.size(), 3);
         EXPECT_EQ(iterB->second[0], 70 * COIN);

         auto iterC = combineBalances.addressBalances_.find(TestChain::scrAddrC);
         ASSERT_NE(iterC, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterC->second.size(), 3);
         EXPECT_EQ(iterC->second[0], 20 * COIN);

         auto iterD = combineBalances.addressBalances_.find(TestChain::scrAddrD);
         ASSERT_NE(iterD, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterD->second.size(), 3);
         EXPECT_EQ(iterD->second[0], 65 * COIN);

         auto iterE = combineBalances.addressBalances_.find(TestChain::scrAddrE);
         ASSERT_NE(iterE, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterE->second.size(), 3);
         EXPECT_EQ(iterE->second[0], 30 * COIN);

         auto iterF = combineBalances.addressBalances_.find(TestChain::scrAddrF);
         ASSERT_NE(iterF, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterF->second.size(), 3);
         EXPECT_EQ(iterF->second[0], 5 * COIN);
      }
   
      //instantiate resolver feed overloaded object
      auto feed = make_shared<ResolverUtils::TestResolverFeed>();
      feed->addPrivKey(TestChain::privKeyAddrB);
      feed->addPrivKey(TestChain::privKeyAddrC);
      feed->addPrivKey(TestChain::privKeyAddrD);
      feed->addPrivKey(TestChain::privKeyAddrE);
      feed->addPrivKey(TestChain::privKeyAddrF);

      //grab utxos for scrAddrB
      auto promUtxo = make_shared<promise<vector<UTXO>>>();
      auto futUtxo = promUtxo->get_future();
      auto getUtxoLbd = [promUtxo](ReturnMessage<vector<UTXO>> msg)->void
      {
         promUtxo->set_value(msg.get());
      };

      wallet1.getSpendableTxOutListForValue(UINT64_MAX, getUtxoLbd);
      vector<UTXO> utxosB;
      {
         auto&& utxoVec = futUtxo.get();
         for (auto& utxo : utxoVec)
         {
            if (utxo.getRecipientScrAddr() != TestChain::scrAddrB)
               continue;

            utxosB.push_back(utxo);
         }
      }

      ASSERT_FALSE(utxosB.empty());

      /*create the transactions*/

      //grab utxo from raw tx
      auto getUtxoFromRawTx = [](BinaryData& rawTx, unsigned id)->UTXO
      {
         Tx tx(rawTx);
         if (id > tx.getNumTxOut())
            throw runtime_error("invalid txout count");

         auto&& txOut = tx.getTxOutCopy(id);

         UTXO utxo;
         utxo.unserializeRaw(txOut.serialize());
         utxo.txOutIndex_ = id;
         utxo.txHash_ = tx.getThisHash();

         return utxo;
      };

      BinaryData rawTx1, rawTx2;

      {
         //20 from B, 5 to A, change to D
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxosB[0]);
         signer.addSpender(spender);

         auto recA = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrA.getSliceCopy(1, 20), 5 * COIN);
         signer.addRecipient(recA);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrD.getSliceCopy(1, 20), 
            spender->getValue() - recA->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx1 = signer.serializeSignedTx();
      }

      {
         auto utxoD = getUtxoFromRawTx(rawTx1, 1);

         //15 from D, 10 to E, change to F
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxoD);
         signer.addSpender(spender);

         auto recE = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrE.getSliceCopy(1, 20), 10 * COIN);
         signer.addRecipient(recE);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrF.getSliceCopy(1, 20), 
            spender->getValue() - recE->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx2 = signer.serializeSignedTx();
      }

      BinaryData rawTx3;
      {
         //10 from E, 5 from F, 3 to A, 2 to E, 5 to D, change to C
         auto zcUtxo1 = getUtxoFromRawTx(rawTx2, 0);
         auto zcUtxo2 = getUtxoFromRawTx(rawTx2, 1);

         Signer signer;
         
         auto spender1 = make_shared<ScriptSpender>(zcUtxo1);
         auto spender2 = make_shared<ScriptSpender>(zcUtxo2);
         signer.addSpender(spender1);
         signer.addSpender(spender2);

         auto recA = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrA.getSliceCopy(1, 20), 3 * COIN);
         signer.addRecipient(recA);

         auto recE = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrE.getSliceCopy(1, 20), 2 * COIN);
         signer.addRecipient(recE);
         
         auto recD = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrD.getSliceCopy(1, 20), 5 * COIN);
         signer.addRecipient(recD);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrC.getSliceCopy(1, 20),
            spender1->getValue() + spender2->getValue() - 
            recA->getValue() - recE->getValue() - recD->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx3 = signer.serializeSignedTx();
      }

      //batch push tx
      auto broadcastId1 = bdvObj->broadcastZC({ rawTx1, rawTx2, rawTx3 });

      Tx tx1(rawTx1);
      Tx tx2(rawTx2);
      Tx tx3(rawTx3);
      
      set<BinaryData> txHashes;
      txHashes.insert(tx1.getThisHash());
      txHashes.insert(tx2.getThisHash());
      txHashes.insert(tx3.getThisHash());

      set<BinaryData> scrAddrSet;
      scrAddrSet.insert(TestChain::scrAddrA);
      scrAddrSet.insert(TestChain::scrAddrB);
      scrAddrSet.insert(TestChain::scrAddrC);
      scrAddrSet.insert(TestChain::scrAddrD);
      scrAddrSet.insert(TestChain::scrAddrE);
      scrAddrSet.insert(TestChain::scrAddrF);

      pCallback->waitOnZc(txHashes, scrAddrSet, broadcastId1);

      //check balances
      combineBalances = getBalances();
      EXPECT_EQ(combineBalances.addressBalances_.size(), 6);

      {
         auto iterA = combineBalances.addressBalances_.find(TestChain::scrAddrA);
         ASSERT_NE(iterA, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterA->second.size(), 3);
         EXPECT_EQ(iterA->second[0], 58 * COIN);

         auto iterB = combineBalances.addressBalances_.find(TestChain::scrAddrB);
         ASSERT_NE(iterB, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterB->second.size(), 3);
         EXPECT_EQ(iterB->second[0], 50 * COIN);

         auto iterC = combineBalances.addressBalances_.find(TestChain::scrAddrC);
         ASSERT_NE(iterC, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterC->second.size(), 3);
         EXPECT_EQ(iterC->second[0], 25 * COIN);

         auto iterD = combineBalances.addressBalances_.find(TestChain::scrAddrD);
         ASSERT_NE(iterD, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterD->second.size(), 3);
         EXPECT_EQ(iterD->second[0], 70 * COIN);

         auto iterE = combineBalances.addressBalances_.find(TestChain::scrAddrE);
         ASSERT_NE(iterE, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterE->second.size(), 3);
         EXPECT_EQ(iterE->second[0], 32 * COIN);

         auto iterF = combineBalances.addressBalances_.find(TestChain::scrAddrF);
         ASSERT_NE(iterF, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterF->second.size(), 3);
         EXPECT_EQ(iterF->second[0], 5 * COIN);
      }
   }

   //cleanup
   auto&& bdvObj2 = AsyncClient::BlockDataViewer::getNewBDV(
      "127.0.0.1", NetworkSettings::listenPort(), ArmoryConfig::getDataDir(),
      authPeersPassLbd_, NetworkSettings::ephemeralPeers(), true, nullptr);
   bdvObj2->addPublicKey(serverPubkey);
   bdvObj2->connectToRemote();

   bdvObj2->shutdown(NetworkSettings::cookie());
   WebSocketServer::waitOnShutdown();

   EXPECT_EQ(theBDMt_->bdm()->zeroConfCont()->getMatcherMapSize(), 0);

   delete theBDMt_;
   theBDMt_ = nullptr;
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_Supernode_WebSocket, BatchZcChain_AlreadyInMempool)
{
   TestUtils::setBlocks({ "0", "1", "2", "3", "4", "5" }, blk0dat_);
   WebSocketServer::initAuthPeers(authPeersPassLbd_);
   WebSocketServer::start(theBDMt_, true);
   auto&& serverPubkey = WebSocketServer::getPublicKey();
   theBDMt_->start(DBSettings::initMode());

   {
      auto pCallback = make_shared<DBTestUtils::UTCallback>();
      auto&& bdvObj = AsyncClient::BlockDataViewer::getNewBDV(
         "127.0.0.1", NetworkSettings::listenPort(), 
         ArmoryConfig::getDataDir(),
         authPeersPassLbd_, 
         NetworkSettings::ephemeralPeers(), true, //public server
         pCallback);
      bdvObj->addPublicKey(serverPubkey);
      bdvObj->connectToRemote();
      bdvObj->registerWithDB(BitcoinSettings::getMagicBytes());

      auto&& wallet1 = bdvObj->instantiateWallet("wallet1");

      vector<BinaryData> _scrAddrVec1;
      _scrAddrVec1.push_back(TestChain::scrAddrA);
      _scrAddrVec1.push_back(TestChain::scrAddrB);
      _scrAddrVec1.push_back(TestChain::scrAddrC);
      _scrAddrVec1.push_back(TestChain::scrAddrD);
      _scrAddrVec1.push_back(TestChain::scrAddrE);
      _scrAddrVec1.push_back(TestChain::scrAddrF);

      vector<string> walletRegIDs;
      walletRegIDs.push_back(
         wallet1.registerAddresses(_scrAddrVec1, false));

      //wait on registration ack
      pCallback->waitOnManySignals(BDMAction_Refresh, walletRegIDs);

      //go online
      bdvObj->goOnline();
      pCallback->waitOnSignal(BDMAction_Ready);

      //balance fetching routine
      vector<string> walletIDs = { wallet1.walletID() };
      auto getBalances = [bdvObj, walletIDs](void)->CombinedBalances
      {
         auto promPtr = make_shared<promise<map<string, CombinedBalances>>>();
         auto fut = promPtr->get_future();
         auto balLbd = [promPtr](
            ReturnMessage<map<string, CombinedBalances>> combBal)->void
         {
            promPtr->set_value(combBal.get());
         };

         bdvObj->getCombinedBalances(walletIDs, balLbd);
         auto&& balMap = fut.get();

         if (balMap.size() != 1)
            throw runtime_error("unexpected balance map size");

         return balMap.begin()->second;
      };

      //check balances before pushing zc
      auto&& combineBalances = getBalances();
      EXPECT_EQ(combineBalances.addressBalances_.size(), 6);

      {
         auto iterA = combineBalances.addressBalances_.find(TestChain::scrAddrA);
         ASSERT_NE(iterA, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterA->second.size(), 3);
         EXPECT_EQ(iterA->second[0], 50 * COIN);

         auto iterB = combineBalances.addressBalances_.find(TestChain::scrAddrB);
         ASSERT_NE(iterB, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterB->second.size(), 3);
         EXPECT_EQ(iterB->second[0], 70 * COIN);

         auto iterC = combineBalances.addressBalances_.find(TestChain::scrAddrC);
         ASSERT_NE(iterC, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterC->second.size(), 3);
         EXPECT_EQ(iterC->second[0], 20 * COIN);

         auto iterD = combineBalances.addressBalances_.find(TestChain::scrAddrD);
         ASSERT_NE(iterD, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterD->second.size(), 3);
         EXPECT_EQ(iterD->second[0], 65 * COIN);

         auto iterE = combineBalances.addressBalances_.find(TestChain::scrAddrE);
         ASSERT_NE(iterE, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterE->second.size(), 3);
         EXPECT_EQ(iterE->second[0], 30 * COIN);

         auto iterF = combineBalances.addressBalances_.find(TestChain::scrAddrF);
         ASSERT_NE(iterF, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterF->second.size(), 3);
         EXPECT_EQ(iterF->second[0], 5 * COIN);
      }
   
      //instantiate resolver feed overloaded object
      auto feed = make_shared<ResolverUtils::TestResolverFeed>();
      feed->addPrivKey(TestChain::privKeyAddrB);
      feed->addPrivKey(TestChain::privKeyAddrC);
      feed->addPrivKey(TestChain::privKeyAddrD);
      feed->addPrivKey(TestChain::privKeyAddrE);
      feed->addPrivKey(TestChain::privKeyAddrF);

      //grab utxos for scrAddrB
      auto promUtxo = make_shared<promise<vector<UTXO>>>();
      auto futUtxo = promUtxo->get_future();
      auto getUtxoLbd = [promUtxo](ReturnMessage<vector<UTXO>> msg)->void
      {
         promUtxo->set_value(msg.get());
      };

      wallet1.getSpendableTxOutListForValue(UINT64_MAX, getUtxoLbd);
      vector<UTXO> utxosB;
      {
         auto&& utxoVec = futUtxo.get();
         for (auto& utxo : utxoVec)
         {
            if (utxo.getRecipientScrAddr() != TestChain::scrAddrB)
               continue;

            utxosB.push_back(utxo);
         }
      }

      ASSERT_FALSE(utxosB.empty());

      /*create the transactions*/

      //grab utxo from raw tx
      auto getUtxoFromRawTx = [](BinaryData& rawTx, unsigned id)->UTXO
      {
         Tx tx(rawTx);
         if (id > tx.getNumTxOut())
            throw runtime_error("invalid txout count");

         auto&& txOut = tx.getTxOutCopy(id);

         UTXO utxo;
         utxo.unserializeRaw(txOut.serialize());
         utxo.txOutIndex_ = id;
         utxo.txHash_ = tx.getThisHash();

         return utxo;
      };

      BinaryData rawTx1, rawTx2;

      {
         //20 from B, 5 to A, change to D
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxosB[0]);
         signer.addSpender(spender);

         auto recA = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrA.getSliceCopy(1, 20), 5 * COIN);
         signer.addRecipient(recA);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrD.getSliceCopy(1, 20), 
            spender->getValue() - recA->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx1 = signer.serializeSignedTx();
      }

      {
         auto utxoD = getUtxoFromRawTx(rawTx1, 1);

         //15 from D, 10 to E, change to F
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxoD);
         signer.addSpender(spender);

         auto recE = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrE.getSliceCopy(1, 20), 10 * COIN);
         signer.addRecipient(recE);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrF.getSliceCopy(1, 20), 
            spender->getValue() - recE->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx2 = signer.serializeSignedTx();
      }

      BinaryData rawTx3;
      {
         //10 from E, 5 from F, 3 to A, 2 to E, 5 to D, change to C
         auto zcUtxo1 = getUtxoFromRawTx(rawTx2, 0);
         auto zcUtxo2 = getUtxoFromRawTx(rawTx2, 1);

         Signer signer;
         
         auto spender1 = make_shared<ScriptSpender>(zcUtxo1);
         auto spender2 = make_shared<ScriptSpender>(zcUtxo2);
         signer.addSpender(spender1);
         signer.addSpender(spender2);

         auto recA = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrA.getSliceCopy(1, 20), 3 * COIN);
         signer.addRecipient(recA);

         auto recE = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrE.getSliceCopy(1, 20), 2 * COIN);
         signer.addRecipient(recE);
         
         auto recD = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrD.getSliceCopy(1, 20), 5 * COIN);
         signer.addRecipient(recD);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrC.getSliceCopy(1, 20),
            spender1->getValue() + spender2->getValue() - 
            recA->getValue() - recE->getValue() - recD->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx3 = signer.serializeSignedTx();
      }
      
      Tx tx1(rawTx1);
      Tx tx2(rawTx2);
      Tx tx3(rawTx3);

      //push first tx
      auto broadcastId1 = bdvObj->broadcastZC(rawTx1);

      set<BinaryData> txHashes;
      txHashes.insert(tx1.getThisHash());

      set<BinaryData> scrAddrSet;
      scrAddrSet.insert(TestChain::scrAddrA);
      scrAddrSet.insert(TestChain::scrAddrB);
      scrAddrSet.insert(TestChain::scrAddrD);

      pCallback->waitOnZc(txHashes, scrAddrSet, broadcastId1);

      //batch push all tx
      auto broadcastId2 = bdvObj->broadcastZC({ rawTx1, rawTx2, rawTx3 });
      
      txHashes.clear();
      txHashes.insert(tx2.getThisHash());
      txHashes.insert(tx3.getThisHash());

      scrAddrSet.clear();
      scrAddrSet.insert(TestChain::scrAddrA);
      scrAddrSet.insert(TestChain::scrAddrC);
      scrAddrSet.insert(TestChain::scrAddrD);
      scrAddrSet.insert(TestChain::scrAddrE);
      scrAddrSet.insert(TestChain::scrAddrF);

      //wait on already in mempool error
      pCallback->waitOnError(tx1.getThisHash(), 
         ArmoryErrorCodes::ZcBroadcast_AlreadyInMempool, broadcastId2);

      //wait on zc notifs
      pCallback->waitOnZc(txHashes, scrAddrSet, broadcastId2);

      //check balances
      combineBalances = getBalances();
      EXPECT_EQ(combineBalances.addressBalances_.size(), 6);

      {
         auto iterA = combineBalances.addressBalances_.find(TestChain::scrAddrA);
         ASSERT_NE(iterA, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterA->second.size(), 3);
         EXPECT_EQ(iterA->second[0], 58 * COIN);

         auto iterB = combineBalances.addressBalances_.find(TestChain::scrAddrB);
         ASSERT_NE(iterB, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterB->second.size(), 3);
         EXPECT_EQ(iterB->second[0], 50 * COIN);

         auto iterC = combineBalances.addressBalances_.find(TestChain::scrAddrC);
         ASSERT_NE(iterC, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterC->second.size(), 3);
         EXPECT_EQ(iterC->second[0], 25 * COIN);

         auto iterD = combineBalances.addressBalances_.find(TestChain::scrAddrD);
         ASSERT_NE(iterD, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterD->second.size(), 3);
         EXPECT_EQ(iterD->second[0], 70 * COIN);

         auto iterE = combineBalances.addressBalances_.find(TestChain::scrAddrE);
         ASSERT_NE(iterE, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterE->second.size(), 3);
         EXPECT_EQ(iterE->second[0], 32 * COIN);

         auto iterF = combineBalances.addressBalances_.find(TestChain::scrAddrF);
         ASSERT_NE(iterF, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterF->second.size(), 3);
         EXPECT_EQ(iterF->second[0], 5 * COIN);
      }
   }

   //cleanup
   auto&& bdvObj2 = AsyncClient::BlockDataViewer::getNewBDV(
      "127.0.0.1", NetworkSettings::listenPort(), ArmoryConfig::getDataDir(),
      authPeersPassLbd_, NetworkSettings::ephemeralPeers(), true, nullptr);
   bdvObj2->addPublicKey(serverPubkey);
   bdvObj2->connectToRemote();

   bdvObj2->shutdown(NetworkSettings::cookie());
   WebSocketServer::waitOnShutdown();

   EXPECT_EQ(theBDMt_->bdm()->zeroConfCont()->getMatcherMapSize(), 0);

   delete theBDMt_;
   theBDMt_ = nullptr;
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_Supernode_WebSocket, BatchZcChain_AlreadyInNodeMempool)
{
   TestUtils::setBlocks({ "0", "1", "2", "3", "4", "5" }, blk0dat_);
   WebSocketServer::initAuthPeers(authPeersPassLbd_);
   WebSocketServer::start(theBDMt_, true);
   auto&& serverPubkey = WebSocketServer::getPublicKey();
   theBDMt_->start(DBSettings::initMode());

   {
      auto pCallback = make_shared<DBTestUtils::UTCallback>();
      auto&& bdvObj = AsyncClient::BlockDataViewer::getNewBDV(
         "127.0.0.1", NetworkSettings::listenPort(), 
         ArmoryConfig::getDataDir(),
         authPeersPassLbd_, 
         NetworkSettings::ephemeralPeers(), true, //public server
         pCallback);
      bdvObj->addPublicKey(serverPubkey);
      bdvObj->connectToRemote();
      bdvObj->registerWithDB(BitcoinSettings::getMagicBytes());

      auto&& wallet1 = bdvObj->instantiateWallet("wallet1");

      vector<BinaryData> _scrAddrVec1;
      _scrAddrVec1.push_back(TestChain::scrAddrA);
      _scrAddrVec1.push_back(TestChain::scrAddrB);
      _scrAddrVec1.push_back(TestChain::scrAddrC);
      _scrAddrVec1.push_back(TestChain::scrAddrD);
      _scrAddrVec1.push_back(TestChain::scrAddrE);
      _scrAddrVec1.push_back(TestChain::scrAddrF);

      vector<string> walletRegIDs;
      walletRegIDs.push_back(
         wallet1.registerAddresses(_scrAddrVec1, false));

      //wait on registration ack
      pCallback->waitOnManySignals(BDMAction_Refresh, walletRegIDs);

      //go online
      bdvObj->goOnline();
      pCallback->waitOnSignal(BDMAction_Ready);

      //balance fetching routine
      vector<string> walletIDs = { wallet1.walletID() };
      auto getBalances = [bdvObj, walletIDs](void)->CombinedBalances
      {
         auto promPtr = make_shared<promise<map<string, CombinedBalances>>>();
         auto fut = promPtr->get_future();
         auto balLbd = [promPtr](
            ReturnMessage<map<string, CombinedBalances>> combBal)->void
         {
            promPtr->set_value(combBal.get());
         };

         bdvObj->getCombinedBalances(walletIDs, balLbd);
         auto&& balMap = fut.get();

         if (balMap.size() != 1)
            throw runtime_error("unexpected balance map size");

         return balMap.begin()->second;
      };

      //check balances before pushing zc
      auto&& combineBalances = getBalances();
      EXPECT_EQ(combineBalances.addressBalances_.size(), 6);

      {
         auto iterA = combineBalances.addressBalances_.find(TestChain::scrAddrA);
         ASSERT_NE(iterA, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterA->second.size(), 3);
         EXPECT_EQ(iterA->second[0], 50 * COIN);

         auto iterB = combineBalances.addressBalances_.find(TestChain::scrAddrB);
         ASSERT_NE(iterB, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterB->second.size(), 3);
         EXPECT_EQ(iterB->second[0], 70 * COIN);

         auto iterC = combineBalances.addressBalances_.find(TestChain::scrAddrC);
         ASSERT_NE(iterC, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterC->second.size(), 3);
         EXPECT_EQ(iterC->second[0], 20 * COIN);

         auto iterD = combineBalances.addressBalances_.find(TestChain::scrAddrD);
         ASSERT_NE(iterD, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterD->second.size(), 3);
         EXPECT_EQ(iterD->second[0], 65 * COIN);

         auto iterE = combineBalances.addressBalances_.find(TestChain::scrAddrE);
         ASSERT_NE(iterE, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterE->second.size(), 3);
         EXPECT_EQ(iterE->second[0], 30 * COIN);

         auto iterF = combineBalances.addressBalances_.find(TestChain::scrAddrF);
         ASSERT_NE(iterF, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterF->second.size(), 3);
         EXPECT_EQ(iterF->second[0], 5 * COIN);
      }
   
      //instantiate resolver feed overloaded object
      auto feed = make_shared<ResolverUtils::TestResolverFeed>();
      feed->addPrivKey(TestChain::privKeyAddrB);
      feed->addPrivKey(TestChain::privKeyAddrC);
      feed->addPrivKey(TestChain::privKeyAddrD);
      feed->addPrivKey(TestChain::privKeyAddrE);
      feed->addPrivKey(TestChain::privKeyAddrF);

      //grab utxos for scrAddrB & scrAddrC
      auto promUtxo = make_shared<promise<vector<UTXO>>>();
      auto futUtxo = promUtxo->get_future();
      auto getUtxoLbd = [promUtxo](ReturnMessage<vector<UTXO>> msg)->void
      {
         promUtxo->set_value(msg.get());
      };

      wallet1.getSpendableTxOutListForValue(UINT64_MAX, getUtxoLbd);
      vector<UTXO> utxosB, utxosC;
      {
         auto&& utxoVec = futUtxo.get();
         for (auto& utxo : utxoVec)
         {
            if (utxo.getRecipientScrAddr() == TestChain::scrAddrB)
               utxosB.push_back(utxo);
            else if (utxo.getRecipientScrAddr() == TestChain::scrAddrC)
               utxosC.push_back(utxo);
         }
      }

      ASSERT_FALSE(utxosB.empty());
      ASSERT_FALSE(utxosC.empty());

      /*create the transactions*/

      //grab utxo from raw tx
      auto getUtxoFromRawTx = [](BinaryData& rawTx, unsigned id)->UTXO
      {
         Tx tx(rawTx);
         if (id > tx.getNumTxOut())
            throw runtime_error("invalid txout count");

         auto&& txOut = tx.getTxOutCopy(id);

         UTXO utxo;
         utxo.unserializeRaw(txOut.serialize());
         utxo.txOutIndex_ = id;
         utxo.txHash_ = tx.getThisHash();

         return utxo;
      };

      BinaryData rawTx1_B;
      {
         //20 from B, 5 to A, change to D
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxosB[0]);
         signer.addSpender(spender);

         auto recA = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrA.getSliceCopy(1, 20), 5 * COIN);
         signer.addRecipient(recA);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrD.getSliceCopy(1, 20), 
            spender->getValue() - recA->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx1_B = signer.serializeSignedTx();
      }

      BinaryData rawTx1_C;
      {
         //20 from C, 5 to E, change to C
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxosC[0]);
         signer.addSpender(spender);

         auto recE = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrE.getSliceCopy(1, 20), 5 * COIN);
         signer.addRecipient(recE);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrC.getSliceCopy(1, 20), 
            spender->getValue() - recE->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx1_C = signer.serializeSignedTx();
      }

      BinaryData rawTx2;
      {
         auto utxoD = getUtxoFromRawTx(rawTx1_B, 1);

         //15 from D, 10 to E, change to F
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxoD);
         signer.addSpender(spender);

         auto recE = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrE.getSliceCopy(1, 20), 10 * COIN);
         signer.addRecipient(recE);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrF.getSliceCopy(1, 20), 
            spender->getValue() - recE->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx2 = signer.serializeSignedTx();
      }

      BinaryData rawTx3;
      {
         //10 from E, 5 from F, 3 to A, 2 to E, 5 to D, change to C
         auto zcUtxo1 = getUtxoFromRawTx(rawTx2, 0);
         auto zcUtxo2 = getUtxoFromRawTx(rawTx2, 1);

         Signer signer;
         
         auto spender1 = make_shared<ScriptSpender>(zcUtxo1);
         auto spender2 = make_shared<ScriptSpender>(zcUtxo2);
         signer.addSpender(spender1);
         signer.addSpender(spender2);

         auto recA = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrA.getSliceCopy(1, 20), 3 * COIN);
         signer.addRecipient(recA);

         auto recE = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrE.getSliceCopy(1, 20), 2 * COIN);
         signer.addRecipient(recE);
         
         auto recD = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrD.getSliceCopy(1, 20), 5 * COIN);
         signer.addRecipient(recD);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrC.getSliceCopy(1, 20),
            spender1->getValue() + spender2->getValue() - 
            recA->getValue() - recE->getValue() - recD->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx3 = signer.serializeSignedTx();
      }
      
      Tx tx1_B(rawTx1_B);
      Tx tx1_C(rawTx1_C);
      Tx tx2(rawTx2);
      Tx tx3(rawTx3);

      //push through the node
      DBTestUtils::ZcVector zcVec;
      zcVec.push_back(rawTx1_B, 1000000000);
      DBTestUtils::pushNewZc(theBDMt_, zcVec, true);

      //batch push all tx
      auto broadcastId1 = bdvObj->broadcastZC({ rawTx1_B, rawTx1_C, rawTx2, rawTx3 });
      
      set<BinaryData> txHashes;
      txHashes.insert(tx1_B.getThisHash());
      txHashes.insert(tx1_C.getThisHash());
      txHashes.insert(tx2.getThisHash());
      txHashes.insert(tx3.getThisHash());

      set<BinaryData> scrAddrSet;
      scrAddrSet.insert(TestChain::scrAddrA);
      scrAddrSet.insert(TestChain::scrAddrB);
      scrAddrSet.insert(TestChain::scrAddrC);
      scrAddrSet.insert(TestChain::scrAddrD);
      scrAddrSet.insert(TestChain::scrAddrE);
      scrAddrSet.insert(TestChain::scrAddrF);

      //wait on zc notifs
      pCallback->waitOnZc(txHashes, scrAddrSet, broadcastId1);

      //check balances
      combineBalances = getBalances();
      EXPECT_EQ(combineBalances.addressBalances_.size(), 6);

      {
         auto iterA = combineBalances.addressBalances_.find(TestChain::scrAddrA);
         ASSERT_NE(iterA, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterA->second.size(), 3);
         EXPECT_EQ(iterA->second[0], 58 * COIN);

         auto iterB = combineBalances.addressBalances_.find(TestChain::scrAddrB);
         ASSERT_NE(iterB, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterB->second.size(), 3);
         EXPECT_EQ(iterB->second[0], 50 * COIN);

         auto iterC = combineBalances.addressBalances_.find(TestChain::scrAddrC);
         ASSERT_NE(iterC, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterC->second.size(), 3);
         EXPECT_EQ(iterC->second[0], 20 * COIN);

         auto iterD = combineBalances.addressBalances_.find(TestChain::scrAddrD);
         ASSERT_NE(iterD, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterD->second.size(), 3);
         EXPECT_EQ(iterD->second[0], 70 * COIN);

         auto iterE = combineBalances.addressBalances_.find(TestChain::scrAddrE);
         ASSERT_NE(iterE, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterE->second.size(), 3);
         EXPECT_EQ(iterE->second[0], 37 * COIN);

         auto iterF = combineBalances.addressBalances_.find(TestChain::scrAddrF);
         ASSERT_NE(iterF, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterF->second.size(), 3);
         EXPECT_EQ(iterF->second[0], 5 * COIN);
      }
   }

   //cleanup
   auto&& bdvObj2 = AsyncClient::BlockDataViewer::getNewBDV(
      "127.0.0.1", NetworkSettings::listenPort(), ArmoryConfig::getDataDir(),
      authPeersPassLbd_, NetworkSettings::ephemeralPeers(), true, nullptr);
   bdvObj2->addPublicKey(serverPubkey);
   bdvObj2->connectToRemote();

   bdvObj2->shutdown(NetworkSettings::cookie());
   WebSocketServer::waitOnShutdown();

   EXPECT_EQ(theBDMt_->bdm()->zeroConfCont()->getMatcherMapSize(), 0);

   delete theBDMt_;
   theBDMt_ = nullptr;
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_Supernode_WebSocket, BatchZcChain_AlreadyInChain)
{
   TestUtils::setBlocks({ "0", "1", "2", "3", "4", "5" }, blk0dat_);
   WebSocketServer::initAuthPeers(authPeersPassLbd_);
   WebSocketServer::start(theBDMt_, true);
   auto&& serverPubkey = WebSocketServer::getPublicKey();
   theBDMt_->start(DBSettings::initMode());

   {
      auto pCallback = make_shared<DBTestUtils::UTCallback>();
      auto&& bdvObj = AsyncClient::BlockDataViewer::getNewBDV(
         "127.0.0.1", NetworkSettings::listenPort(), 
         ArmoryConfig::getDataDir(),
         authPeersPassLbd_, 
         NetworkSettings::ephemeralPeers(), true, //public server
         pCallback);
      bdvObj->addPublicKey(serverPubkey);
      bdvObj->connectToRemote();
      bdvObj->registerWithDB(BitcoinSettings::getMagicBytes());

      auto&& wallet1 = bdvObj->instantiateWallet("wallet1");

      vector<BinaryData> _scrAddrVec1;
      _scrAddrVec1.push_back(TestChain::scrAddrA);
      _scrAddrVec1.push_back(TestChain::scrAddrB);
      _scrAddrVec1.push_back(TestChain::scrAddrC);
      _scrAddrVec1.push_back(TestChain::scrAddrD);
      _scrAddrVec1.push_back(TestChain::scrAddrE);
      _scrAddrVec1.push_back(TestChain::scrAddrF);

      vector<string> walletRegIDs;
      walletRegIDs.push_back(
         wallet1.registerAddresses(_scrAddrVec1, false));

      //wait on registration ack
      pCallback->waitOnManySignals(BDMAction_Refresh, walletRegIDs);

      //go online
      bdvObj->goOnline();
      pCallback->waitOnSignal(BDMAction_Ready);

      //balance fetching routine
      vector<string> walletIDs = { wallet1.walletID() };
      auto getBalances = [bdvObj, walletIDs](void)->CombinedBalances
      {
         auto promPtr = make_shared<promise<map<string, CombinedBalances>>>();
         auto fut = promPtr->get_future();
         auto balLbd = [promPtr](
            ReturnMessage<map<string, CombinedBalances>> combBal)->void
         {
            promPtr->set_value(combBal.get());
         };

         bdvObj->getCombinedBalances(walletIDs, balLbd);
         auto&& balMap = fut.get();

         if (balMap.size() != 1)
            throw runtime_error("unexpected balance map size");

         return balMap.begin()->second;
      };

      //check balances before pushing zc
      auto&& combineBalances = getBalances();
      EXPECT_EQ(combineBalances.addressBalances_.size(), 6);

      {
         auto iterA = combineBalances.addressBalances_.find(TestChain::scrAddrA);
         ASSERT_NE(iterA, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterA->second.size(), 3);
         EXPECT_EQ(iterA->second[0], 50 * COIN);

         auto iterB = combineBalances.addressBalances_.find(TestChain::scrAddrB);
         ASSERT_NE(iterB, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterB->second.size(), 3);
         EXPECT_EQ(iterB->second[0], 70 * COIN);

         auto iterC = combineBalances.addressBalances_.find(TestChain::scrAddrC);
         ASSERT_NE(iterC, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterC->second.size(), 3);
         EXPECT_EQ(iterC->second[0], 20 * COIN);

         auto iterD = combineBalances.addressBalances_.find(TestChain::scrAddrD);
         ASSERT_NE(iterD, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterD->second.size(), 3);
         EXPECT_EQ(iterD->second[0], 65 * COIN);

         auto iterE = combineBalances.addressBalances_.find(TestChain::scrAddrE);
         ASSERT_NE(iterE, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterE->second.size(), 3);
         EXPECT_EQ(iterE->second[0], 30 * COIN);

         auto iterF = combineBalances.addressBalances_.find(TestChain::scrAddrF);
         ASSERT_NE(iterF, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterF->second.size(), 3);
         EXPECT_EQ(iterF->second[0], 5 * COIN);
      }
   
      //instantiate resolver feed overloaded object
      auto feed = make_shared<ResolverUtils::TestResolverFeed>();
      feed->addPrivKey(TestChain::privKeyAddrB);
      feed->addPrivKey(TestChain::privKeyAddrC);
      feed->addPrivKey(TestChain::privKeyAddrD);
      feed->addPrivKey(TestChain::privKeyAddrE);
      feed->addPrivKey(TestChain::privKeyAddrF);

      //grab utxos for scrAddrB & scrAddrC
      auto promUtxo = make_shared<promise<vector<UTXO>>>();
      auto futUtxo = promUtxo->get_future();
      auto getUtxoLbd = [promUtxo](ReturnMessage<vector<UTXO>> msg)->void
      {
         promUtxo->set_value(msg.get());
      };

      wallet1.getSpendableTxOutListForValue(UINT64_MAX, getUtxoLbd);
      vector<UTXO> utxosB, utxosC;
      {
         auto&& utxoVec = futUtxo.get();
         for (auto& utxo : utxoVec)
         {
            if (utxo.getRecipientScrAddr() == TestChain::scrAddrB)
               utxosB.push_back(utxo);
            else if (utxo.getRecipientScrAddr() == TestChain::scrAddrC)
               utxosC.push_back(utxo);
         }
      }

      ASSERT_FALSE(utxosB.empty());
      ASSERT_FALSE(utxosC.empty());

      /*create the transactions*/

      //grab utxo from raw tx
      auto getUtxoFromRawTx = [](BinaryData& rawTx, unsigned id)->UTXO
      {
         Tx tx(rawTx);
         if (id > tx.getNumTxOut())
            throw runtime_error("invalid txout count");

         auto&& txOut = tx.getTxOutCopy(id);

         UTXO utxo;
         utxo.unserializeRaw(txOut.serialize());
         utxo.txOutIndex_ = id;
         utxo.txHash_ = tx.getThisHash();

         return utxo;
      };

      BinaryData rawTx1_B;
      {
         //20 from B, 5 to A, change to D
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxosB[0]);
         signer.addSpender(spender);

         auto recA = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrA.getSliceCopy(1, 20), 5 * COIN);
         signer.addRecipient(recA);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrD.getSliceCopy(1, 20), 
            spender->getValue() - recA->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx1_B = signer.serializeSignedTx();
      }

      BinaryData rawTx1_C;
      {
         //20 from C, 5 to E, change to C
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxosC[0]);
         signer.addSpender(spender);

         auto recE = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrE.getSliceCopy(1, 20), 5 * COIN);
         signer.addRecipient(recE);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrC.getSliceCopy(1, 20), 
            spender->getValue() - recE->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx1_C = signer.serializeSignedTx();
      }

      BinaryData rawTx2;
      {
         auto utxoD = getUtxoFromRawTx(rawTx1_B, 1);

         //15 from D, 10 to E, change to F
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxoD);
         signer.addSpender(spender);

         auto recE = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrE.getSliceCopy(1, 20), 10 * COIN);
         signer.addRecipient(recE);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrF.getSliceCopy(1, 20), 
            spender->getValue() - recE->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx2 = signer.serializeSignedTx();
      }

      BinaryData rawTx3;
      {
         //10 from E, 5 from F, 3 to A, 2 to E, 5 to D, change to C
         auto zcUtxo1 = getUtxoFromRawTx(rawTx2, 0);
         auto zcUtxo2 = getUtxoFromRawTx(rawTx2, 1);

         Signer signer;
         
         auto spender1 = make_shared<ScriptSpender>(zcUtxo1);
         auto spender2 = make_shared<ScriptSpender>(zcUtxo2);
         signer.addSpender(spender1);
         signer.addSpender(spender2);

         auto recA = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrA.getSliceCopy(1, 20), 3 * COIN);
         signer.addRecipient(recA);

         auto recE = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrE.getSliceCopy(1, 20), 2 * COIN);
         signer.addRecipient(recE);
         
         auto recD = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrD.getSliceCopy(1, 20), 5 * COIN);
         signer.addRecipient(recD);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrC.getSliceCopy(1, 20),
            spender1->getValue() + spender2->getValue() - 
            recA->getValue() - recE->getValue() - recD->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx3 = signer.serializeSignedTx();
      }
      
      Tx tx1_B(rawTx1_B);
      Tx tx1_C(rawTx1_C);
      Tx tx2(rawTx2);
      Tx tx3(rawTx3);

      //push through the node
      DBTestUtils::ZcVector zcVec;
      zcVec.push_back(rawTx1_B, 1000000000);
      DBTestUtils::pushNewZc(theBDMt_, zcVec, true);

      //mine 1 block
      DBTestUtils::mineNewBlock(theBDMt_, CryptoPRNG::generateRandom(20), 1);
      pCallback->waitOnSignal(BDMAction_NewBlock);

      //batch push all tx
      auto broadcastId1 = bdvObj->broadcastZC({ rawTx1_B, rawTx1_C, rawTx2, rawTx3 });
      
      set<BinaryData> txHashes;
      txHashes.insert(tx1_C.getThisHash());
      txHashes.insert(tx2.getThisHash());
      txHashes.insert(tx3.getThisHash());

      set<BinaryData> scrAddrSet;
      scrAddrSet.insert(TestChain::scrAddrA);
      scrAddrSet.insert(TestChain::scrAddrC);
      scrAddrSet.insert(TestChain::scrAddrD);
      scrAddrSet.insert(TestChain::scrAddrE);
      scrAddrSet.insert(TestChain::scrAddrF);

      //wait on zc notifs
      pCallback->waitOnZc(txHashes, scrAddrSet, broadcastId1);

      //check balances
      combineBalances = getBalances();
      EXPECT_EQ(combineBalances.addressBalances_.size(), 6);

      {
         auto iterA = combineBalances.addressBalances_.find(TestChain::scrAddrA);
         ASSERT_NE(iterA, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterA->second.size(), 3);
         EXPECT_EQ(iterA->second[0], 58 * COIN);

         auto iterB = combineBalances.addressBalances_.find(TestChain::scrAddrB);
         ASSERT_NE(iterB, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterB->second.size(), 3);
         EXPECT_EQ(iterB->second[0], 50 * COIN);

         auto iterC = combineBalances.addressBalances_.find(TestChain::scrAddrC);
         ASSERT_NE(iterC, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterC->second.size(), 3);
         EXPECT_EQ(iterC->second[0], 20 * COIN);

         auto iterD = combineBalances.addressBalances_.find(TestChain::scrAddrD);
         ASSERT_NE(iterD, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterD->second.size(), 3);
         EXPECT_EQ(iterD->second[0], 70 * COIN);

         auto iterE = combineBalances.addressBalances_.find(TestChain::scrAddrE);
         ASSERT_NE(iterE, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterE->second.size(), 3);
         EXPECT_EQ(iterE->second[0], 37 * COIN);

         auto iterF = combineBalances.addressBalances_.find(TestChain::scrAddrF);
         ASSERT_NE(iterF, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterF->second.size(), 3);
         EXPECT_EQ(iterF->second[0], 5 * COIN);
      }
   }

   //cleanup
   auto&& bdvObj2 = AsyncClient::BlockDataViewer::getNewBDV(
      "127.0.0.1", NetworkSettings::listenPort(), ArmoryConfig::getDataDir(),
      authPeersPassLbd_, NetworkSettings::ephemeralPeers(), true, nullptr);
   bdvObj2->addPublicKey(serverPubkey);
   bdvObj2->connectToRemote();

   bdvObj2->shutdown(NetworkSettings::cookie());
   WebSocketServer::waitOnShutdown();

   EXPECT_EQ(theBDMt_->bdm()->zeroConfCont()->getMatcherMapSize(), 0);

   delete theBDMt_;
   theBDMt_ = nullptr;
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_Supernode_WebSocket, BatchZcChain_MissInv)
{
   TestUtils::setBlocks({ "0", "1", "2", "3", "4", "5" }, blk0dat_);
   WebSocketServer::initAuthPeers(authPeersPassLbd_);
   WebSocketServer::start(theBDMt_, true);
   auto&& serverPubkey = WebSocketServer::getPublicKey();
   theBDMt_->start(DBSettings::initMode());

   {
      auto pCallback = make_shared<DBTestUtils::UTCallback>();
      auto&& bdvObj = AsyncClient::BlockDataViewer::getNewBDV(
         "127.0.0.1", NetworkSettings::listenPort(), 
         ArmoryConfig::getDataDir(),
         authPeersPassLbd_, 
         NetworkSettings::ephemeralPeers(), true, //public server
         pCallback);
      bdvObj->addPublicKey(serverPubkey);
      bdvObj->connectToRemote();
      bdvObj->registerWithDB(BitcoinSettings::getMagicBytes());

      auto&& wallet1 = bdvObj->instantiateWallet("wallet1");

      vector<BinaryData> _scrAddrVec1;
      _scrAddrVec1.push_back(TestChain::scrAddrA);
      _scrAddrVec1.push_back(TestChain::scrAddrB);
      _scrAddrVec1.push_back(TestChain::scrAddrC);
      _scrAddrVec1.push_back(TestChain::scrAddrD);
      _scrAddrVec1.push_back(TestChain::scrAddrE);
      _scrAddrVec1.push_back(TestChain::scrAddrF);

      vector<string> walletRegIDs;
      walletRegIDs.push_back(
         wallet1.registerAddresses(_scrAddrVec1, false));

      //wait on registration ack
      pCallback->waitOnManySignals(BDMAction_Refresh, walletRegIDs);

      //go online
      bdvObj->goOnline();
      pCallback->waitOnSignal(BDMAction_Ready);

      //balance fetching routine
      vector<string> walletIDs = { wallet1.walletID() };
      auto getBalances = [bdvObj, walletIDs](void)->CombinedBalances
      {
         auto promPtr = make_shared<promise<map<string, CombinedBalances>>>();
         auto fut = promPtr->get_future();
         auto balLbd = [promPtr](
            ReturnMessage<map<string, CombinedBalances>> combBal)->void
         {
            promPtr->set_value(combBal.get());
         };

         bdvObj->getCombinedBalances(walletIDs, balLbd);
         auto&& balMap = fut.get();

         if (balMap.size() != 1)
            throw runtime_error("unexpected balance map size");

         return balMap.begin()->second;
      };

      //check balances before pushing zc
      auto&& combineBalances = getBalances();
      EXPECT_EQ(combineBalances.addressBalances_.size(), 6);

      {
         auto iterA = combineBalances.addressBalances_.find(TestChain::scrAddrA);
         ASSERT_NE(iterA, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterA->second.size(), 3);
         EXPECT_EQ(iterA->second[0], 50 * COIN);

         auto iterB = combineBalances.addressBalances_.find(TestChain::scrAddrB);
         ASSERT_NE(iterB, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterB->second.size(), 3);
         EXPECT_EQ(iterB->second[0], 70 * COIN);

         auto iterC = combineBalances.addressBalances_.find(TestChain::scrAddrC);
         ASSERT_NE(iterC, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterC->second.size(), 3);
         EXPECT_EQ(iterC->second[0], 20 * COIN);

         auto iterD = combineBalances.addressBalances_.find(TestChain::scrAddrD);
         ASSERT_NE(iterD, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterD->second.size(), 3);
         EXPECT_EQ(iterD->second[0], 65 * COIN);

         auto iterE = combineBalances.addressBalances_.find(TestChain::scrAddrE);
         ASSERT_NE(iterE, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterE->second.size(), 3);
         EXPECT_EQ(iterE->second[0], 30 * COIN);

         auto iterF = combineBalances.addressBalances_.find(TestChain::scrAddrF);
         ASSERT_NE(iterF, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterF->second.size(), 3);
         EXPECT_EQ(iterF->second[0], 5 * COIN);
      }
   
      //instantiate resolver feed overloaded object
      auto feed = make_shared<ResolverUtils::TestResolverFeed>();
      feed->addPrivKey(TestChain::privKeyAddrB);
      feed->addPrivKey(TestChain::privKeyAddrC);
      feed->addPrivKey(TestChain::privKeyAddrD);
      feed->addPrivKey(TestChain::privKeyAddrE);
      feed->addPrivKey(TestChain::privKeyAddrF);

      //grab utxos for scrAddrB & scrAddrC
      auto promUtxo = make_shared<promise<vector<UTXO>>>();
      auto futUtxo = promUtxo->get_future();
      auto getUtxoLbd = [promUtxo](ReturnMessage<vector<UTXO>> msg)->void
      {
         promUtxo->set_value(msg.get());
      };

      wallet1.getSpendableTxOutListForValue(UINT64_MAX, getUtxoLbd);
      vector<UTXO> utxosB, utxosC;
      {
         auto&& utxoVec = futUtxo.get();
         for (auto& utxo : utxoVec)
         {
            if (utxo.getRecipientScrAddr() == TestChain::scrAddrB)
               utxosB.push_back(utxo);
            else if (utxo.getRecipientScrAddr() == TestChain::scrAddrC)
               utxosC.push_back(utxo);
         }
      }

      ASSERT_FALSE(utxosB.empty());
      ASSERT_FALSE(utxosC.empty());

      /*create the transactions*/

      //grab utxo from raw tx
      auto getUtxoFromRawTx = [](BinaryData& rawTx, unsigned id)->UTXO
      {
         Tx tx(rawTx);
         if (id > tx.getNumTxOut())
            throw runtime_error("invalid txout count");

         auto&& txOut = tx.getTxOutCopy(id);

         UTXO utxo;
         utxo.unserializeRaw(txOut.serialize());
         utxo.txOutIndex_ = id;
         utxo.txHash_ = tx.getThisHash();

         return utxo;
      };

      BinaryData rawTx1_B;
      {
         //20 from B, 5 to A, change to D
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxosB[0]);
         signer.addSpender(spender);

         auto recA = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrA.getSliceCopy(1, 20), 5 * COIN);
         signer.addRecipient(recA);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrD.getSliceCopy(1, 20), 
            spender->getValue() - recA->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx1_B = signer.serializeSignedTx();
      }

      BinaryData rawTx1_C;
      {
         //20 from C, 5 to E, change to C
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxosC[0]);
         signer.addSpender(spender);

         auto recE = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrE.getSliceCopy(1, 20), 5 * COIN);
         signer.addRecipient(recE);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrC.getSliceCopy(1, 20), 
            spender->getValue() - recE->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx1_C = signer.serializeSignedTx();
      }

      BinaryData rawTx2;
      {
         auto utxoD = getUtxoFromRawTx(rawTx1_B, 1);

         //15 from D, 10 to E, change to F
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxoD);
         signer.addSpender(spender);

         auto recE = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrE.getSliceCopy(1, 20), 10 * COIN);
         signer.addRecipient(recE);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrF.getSliceCopy(1, 20), 
            spender->getValue() - recE->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx2 = signer.serializeSignedTx();
      }

      BinaryData rawTx3;
      {
         //10 from E, 5 from F, 3 to A, 2 to E, 5 to D, change to C
         auto zcUtxo1 = getUtxoFromRawTx(rawTx2, 0);
         auto zcUtxo2 = getUtxoFromRawTx(rawTx2, 1);

         Signer signer;
         
         auto spender1 = make_shared<ScriptSpender>(zcUtxo1);
         auto spender2 = make_shared<ScriptSpender>(zcUtxo2);
         signer.addSpender(spender1);
         signer.addSpender(spender2);

         auto recA = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrA.getSliceCopy(1, 20), 3 * COIN);
         signer.addRecipient(recA);

         auto recE = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrE.getSliceCopy(1, 20), 2 * COIN);
         signer.addRecipient(recE);
         
         auto recD = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrD.getSliceCopy(1, 20), 5 * COIN);
         signer.addRecipient(recD);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrC.getSliceCopy(1, 20),
            spender1->getValue() + spender2->getValue() - 
            recA->getValue() - recE->getValue() - recD->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx3 = signer.serializeSignedTx();
      }
      
      Tx tx1_B(rawTx1_B);
      Tx tx1_C(rawTx1_C);
      Tx tx2(rawTx2);
      Tx tx3(rawTx3);

      //push through the node
      nodePtr_->presentZcHash(tx2.getThisHash());

      //batch push all tx
      auto broadcastId1 = bdvObj->broadcastZC({ rawTx1_B, rawTx1_C, rawTx2, rawTx3 });
      
      set<BinaryData> txHashes;
      txHashes.insert(tx1_B.getThisHash());
      txHashes.insert(tx1_C.getThisHash());
      txHashes.insert(tx2.getThisHash());
      txHashes.insert(tx3.getThisHash());

      set<BinaryData> scrAddrSet;
      scrAddrSet.insert(TestChain::scrAddrA);
      scrAddrSet.insert(TestChain::scrAddrB);
      scrAddrSet.insert(TestChain::scrAddrC);
      scrAddrSet.insert(TestChain::scrAddrD);
      scrAddrSet.insert(TestChain::scrAddrE);
      scrAddrSet.insert(TestChain::scrAddrF);

      //wait on zc notifs
      pCallback->waitOnZc(txHashes, scrAddrSet, broadcastId1);

      //check balances
      combineBalances = getBalances();
      EXPECT_EQ(combineBalances.addressBalances_.size(), 6);

      {
         auto iterA = combineBalances.addressBalances_.find(TestChain::scrAddrA);
         ASSERT_NE(iterA, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterA->second.size(), 3);
         EXPECT_EQ(iterA->second[0], 58 * COIN);

         auto iterB = combineBalances.addressBalances_.find(TestChain::scrAddrB);
         ASSERT_NE(iterB, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterB->second.size(), 3);
         EXPECT_EQ(iterB->second[0], 50 * COIN);

         auto iterC = combineBalances.addressBalances_.find(TestChain::scrAddrC);
         ASSERT_NE(iterC, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterC->second.size(), 3);
         EXPECT_EQ(iterC->second[0], 20 * COIN);

         auto iterD = combineBalances.addressBalances_.find(TestChain::scrAddrD);
         ASSERT_NE(iterD, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterD->second.size(), 3);
         EXPECT_EQ(iterD->second[0], 70 * COIN);

         auto iterE = combineBalances.addressBalances_.find(TestChain::scrAddrE);
         ASSERT_NE(iterE, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterE->second.size(), 3);
         EXPECT_EQ(iterE->second[0], 37 * COIN);

         auto iterF = combineBalances.addressBalances_.find(TestChain::scrAddrF);
         ASSERT_NE(iterF, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterF->second.size(), 3);
         EXPECT_EQ(iterF->second[0], 5 * COIN);
      }
   }

   //cleanup
   auto&& bdvObj2 = AsyncClient::BlockDataViewer::getNewBDV(
      "127.0.0.1", NetworkSettings::listenPort(), ArmoryConfig::getDataDir(),
      authPeersPassLbd_, NetworkSettings::ephemeralPeers(), true, nullptr);
   bdvObj2->addPublicKey(serverPubkey);
   bdvObj2->connectToRemote();

   bdvObj2->shutdown(NetworkSettings::cookie());
   WebSocketServer::waitOnShutdown();

   EXPECT_EQ(theBDMt_->bdm()->zeroConfCont()->getMatcherMapSize(), 0);

   delete theBDMt_;
   theBDMt_ = nullptr;
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_Supernode_WebSocket, BatchZcChain_ConflictingChildren)
{
   TestUtils::setBlocks({ "0", "1", "2", "3", "4", "5" }, blk0dat_);
   WebSocketServer::initAuthPeers(authPeersPassLbd_);
   WebSocketServer::start(theBDMt_, true);
   auto&& serverPubkey = WebSocketServer::getPublicKey();
   theBDMt_->start(DBSettings::initMode());

   {
      auto pCallback = make_shared<DBTestUtils::UTCallback>();
      auto&& bdvObj = AsyncClient::BlockDataViewer::getNewBDV(
         "127.0.0.1", NetworkSettings::listenPort(), 
         ArmoryConfig::getDataDir(),
         authPeersPassLbd_, 
         NetworkSettings::ephemeralPeers(), true, //public server
         pCallback);
      bdvObj->addPublicKey(serverPubkey);
      bdvObj->connectToRemote();
      bdvObj->registerWithDB(BitcoinSettings::getMagicBytes());

      auto&& wallet1 = bdvObj->instantiateWallet("wallet1");

      vector<BinaryData> _scrAddrVec1;
      _scrAddrVec1.push_back(TestChain::scrAddrA);
      _scrAddrVec1.push_back(TestChain::scrAddrB);
      _scrAddrVec1.push_back(TestChain::scrAddrC);
      _scrAddrVec1.push_back(TestChain::scrAddrD);
      _scrAddrVec1.push_back(TestChain::scrAddrE);
      _scrAddrVec1.push_back(TestChain::scrAddrF);

      vector<string> walletRegIDs;
      walletRegIDs.push_back(
         wallet1.registerAddresses(_scrAddrVec1, false));

      //wait on registration ack
      pCallback->waitOnManySignals(BDMAction_Refresh, walletRegIDs);

      //go online
      bdvObj->goOnline();
      pCallback->waitOnSignal(BDMAction_Ready);

      //balance fetching routine
      vector<string> walletIDs = { wallet1.walletID() };
      auto getBalances = [bdvObj, walletIDs](void)->CombinedBalances
      {
         auto promPtr = make_shared<promise<map<string, CombinedBalances>>>();
         auto fut = promPtr->get_future();
         auto balLbd = [promPtr](
            ReturnMessage<map<string, CombinedBalances>> combBal)->void
         {
            promPtr->set_value(combBal.get());
         };

         bdvObj->getCombinedBalances(walletIDs, balLbd);
         auto&& balMap = fut.get();

         if (balMap.size() != 1)
            throw runtime_error("unexpected balance map size");

         return balMap.begin()->second;
      };

      //check balances before pushing zc
      auto&& combineBalances = getBalances();
      EXPECT_EQ(combineBalances.addressBalances_.size(), 6);

      {
         auto iterA = combineBalances.addressBalances_.find(TestChain::scrAddrA);
         ASSERT_NE(iterA, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterA->second.size(), 3);
         EXPECT_EQ(iterA->second[0], 50 * COIN);

         auto iterB = combineBalances.addressBalances_.find(TestChain::scrAddrB);
         ASSERT_NE(iterB, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterB->second.size(), 3);
         EXPECT_EQ(iterB->second[0], 70 * COIN);

         auto iterC = combineBalances.addressBalances_.find(TestChain::scrAddrC);
         ASSERT_NE(iterC, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterC->second.size(), 3);
         EXPECT_EQ(iterC->second[0], 20 * COIN);

         auto iterD = combineBalances.addressBalances_.find(TestChain::scrAddrD);
         ASSERT_NE(iterD, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterD->second.size(), 3);
         EXPECT_EQ(iterD->second[0], 65 * COIN);

         auto iterE = combineBalances.addressBalances_.find(TestChain::scrAddrE);
         ASSERT_NE(iterE, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterE->second.size(), 3);
         EXPECT_EQ(iterE->second[0], 30 * COIN);

         auto iterF = combineBalances.addressBalances_.find(TestChain::scrAddrF);
         ASSERT_NE(iterF, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterF->second.size(), 3);
         EXPECT_EQ(iterF->second[0], 5 * COIN);
      }
   
      //instantiate resolver feed overloaded object
      auto feed = make_shared<ResolverUtils::TestResolverFeed>();
      feed->addPrivKey(TestChain::privKeyAddrB);
      feed->addPrivKey(TestChain::privKeyAddrC);
      feed->addPrivKey(TestChain::privKeyAddrD);
      feed->addPrivKey(TestChain::privKeyAddrE);
      feed->addPrivKey(TestChain::privKeyAddrF);

      //grab utxos for scrAddrB & scrAddrC
      auto promUtxo = make_shared<promise<vector<UTXO>>>();
      auto futUtxo = promUtxo->get_future();
      auto getUtxoLbd = [promUtxo](ReturnMessage<vector<UTXO>> msg)->void
      {
         promUtxo->set_value(msg.get());
      };

      wallet1.getSpendableTxOutListForValue(UINT64_MAX, getUtxoLbd);
      vector<UTXO> utxosB, utxosC;
      {
         auto&& utxoVec = futUtxo.get();
         for (auto& utxo : utxoVec)
         {
            if (utxo.getRecipientScrAddr() == TestChain::scrAddrB)
               utxosB.push_back(utxo);
            else if (utxo.getRecipientScrAddr() == TestChain::scrAddrC)
               utxosC.push_back(utxo);
         }
      }

      ASSERT_FALSE(utxosB.empty());
      ASSERT_FALSE(utxosC.empty());

      /*create the transactions*/

      //grab utxo from raw tx
      auto getUtxoFromRawTx = [](BinaryData& rawTx, unsigned id)->UTXO
      {
         Tx tx(rawTx);
         if (id > tx.getNumTxOut())
            throw runtime_error("invalid txout count");

         auto&& txOut = tx.getTxOutCopy(id);

         UTXO utxo;
         utxo.unserializeRaw(txOut.serialize());
         utxo.txOutIndex_ = id;
         utxo.txHash_ = tx.getThisHash();

         return utxo;
      };

      BinaryData rawTx1_B;
      {
         //20 from B, 5 to A, change to D
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxosB[0]);
         signer.addSpender(spender);

         auto recA = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrA.getSliceCopy(1, 20), 5 * COIN);
         signer.addRecipient(recA);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrD.getSliceCopy(1, 20), 
            spender->getValue() - recA->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx1_B = signer.serializeSignedTx();
      }

      BinaryData rawTx1_C;
      {
         //20 from C, 5 to E, change to C
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxosC[0]);
         signer.addSpender(spender);

         auto recE = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrE.getSliceCopy(1, 20), 5 * COIN);
         signer.addRecipient(recE);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrC.getSliceCopy(1, 20), 
            spender->getValue() - recE->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx1_C = signer.serializeSignedTx();
      }

      BinaryData rawTx2;
      {
         auto utxoD = getUtxoFromRawTx(rawTx1_B, 1);

         //15 from D, 10 to E, change to F
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxoD);
         signer.addSpender(spender);

         auto recE = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrE.getSliceCopy(1, 20), 10 * COIN);
         signer.addRecipient(recE);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrF.getSliceCopy(1, 20), 
            spender->getValue() - recE->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx2 = signer.serializeSignedTx();
      }

      BinaryData rawTx3;
      {
         auto utxoD = getUtxoFromRawTx(rawTx1_B, 1);

         //15 from D, 10 to E, change to A
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxoD);
         signer.addSpender(spender);

         auto recE = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrE.getSliceCopy(1, 20), 10 * COIN);
         signer.addRecipient(recE);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrA.getSliceCopy(1, 20), 
            spender->getValue() - recE->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx3 = signer.serializeSignedTx();
      }
      
      Tx tx1_B(rawTx1_B);
      Tx tx1_C(rawTx1_C);
      Tx tx2(rawTx2);
      Tx tx3(rawTx3);

      //batch push all tx
      auto broadcastId1 = bdvObj->broadcastZC({ rawTx1_B, rawTx1_C, rawTx2, rawTx3 });
      
      set<BinaryData> txHashes;
      txHashes.insert(tx1_B.getThisHash());
      txHashes.insert(tx1_C.getThisHash());
      txHashes.insert(tx2.getThisHash());
      txHashes.insert(tx3.getThisHash());

      set<BinaryData> scrAddrSet;
      scrAddrSet.insert(TestChain::scrAddrA);
      scrAddrSet.insert(TestChain::scrAddrB);
      scrAddrSet.insert(TestChain::scrAddrC);
      scrAddrSet.insert(TestChain::scrAddrD);
      scrAddrSet.insert(TestChain::scrAddrE);
      scrAddrSet.insert(TestChain::scrAddrF);

      //wait on zc error for conflicting child
      pCallback->waitOnError(
         tx3.getThisHash(), ArmoryErrorCodes::ZcBroadcast_VerifyRejected, broadcastId1);

      //wait on zc notifs
      pCallback->waitOnZc(txHashes, scrAddrSet, broadcastId1);

      //check balances
      combineBalances = getBalances();
      EXPECT_EQ(combineBalances.addressBalances_.size(), 6);

      {
         auto iterA = combineBalances.addressBalances_.find(TestChain::scrAddrA);
         ASSERT_NE(iterA, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterA->second.size(), 3);
         EXPECT_EQ(iterA->second[0], 55 * COIN);

         auto iterB = combineBalances.addressBalances_.find(TestChain::scrAddrB);
         ASSERT_NE(iterB, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterB->second.size(), 3);
         EXPECT_EQ(iterB->second[0], 50 * COIN);

         auto iterC = combineBalances.addressBalances_.find(TestChain::scrAddrC);
         ASSERT_NE(iterC, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterC->second.size(), 3);
         EXPECT_EQ(iterC->second[0], 15 * COIN);

         auto iterD = combineBalances.addressBalances_.find(TestChain::scrAddrD);
         ASSERT_NE(iterD, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterD->second.size(), 3);
         EXPECT_EQ(iterD->second[0], 65 * COIN);

         auto iterE = combineBalances.addressBalances_.find(TestChain::scrAddrE);
         ASSERT_NE(iterE, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterE->second.size(), 3);
         EXPECT_EQ(iterE->second[0], 45 * COIN);

         auto iterF = combineBalances.addressBalances_.find(TestChain::scrAddrF);
         ASSERT_NE(iterF, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterF->second.size(), 3);
         EXPECT_EQ(iterF->second[0], 10 * COIN);
      }
   }

   //cleanup
   auto&& bdvObj2 = AsyncClient::BlockDataViewer::getNewBDV(
      "127.0.0.1", NetworkSettings::listenPort(), ArmoryConfig::getDataDir(),
      authPeersPassLbd_, NetworkSettings::ephemeralPeers(), true, nullptr);
   bdvObj2->addPublicKey(serverPubkey);
   bdvObj2->connectToRemote();

   bdvObj2->shutdown(NetworkSettings::cookie());
   WebSocketServer::waitOnShutdown();

   EXPECT_EQ(theBDMt_->bdm()->zeroConfCont()->getMatcherMapSize(), 0);

   delete theBDMt_;
   theBDMt_ = nullptr;
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_Supernode_WebSocket, BatchZcChain_ConflictingChildren_AlreadyInChain1)
{
   TestUtils::setBlocks({ "0", "1", "2", "3", "4", "5" }, blk0dat_);
   WebSocketServer::initAuthPeers(authPeersPassLbd_);
   WebSocketServer::start(theBDMt_, true);
   auto&& serverPubkey = WebSocketServer::getPublicKey();
   theBDMt_->start(DBSettings::initMode());

   {
      auto pCallback = make_shared<DBTestUtils::UTCallback>();
      auto&& bdvObj = AsyncClient::BlockDataViewer::getNewBDV(
         "127.0.0.1", NetworkSettings::listenPort(), 
         ArmoryConfig::getDataDir(),
         authPeersPassLbd_, 
         NetworkSettings::ephemeralPeers(), true, //public server
         pCallback);
      bdvObj->addPublicKey(serverPubkey);
      bdvObj->connectToRemote();
      bdvObj->registerWithDB(BitcoinSettings::getMagicBytes());

      auto&& wallet1 = bdvObj->instantiateWallet("wallet1");

      vector<BinaryData> _scrAddrVec1;
      _scrAddrVec1.push_back(TestChain::scrAddrA);
      _scrAddrVec1.push_back(TestChain::scrAddrB);
      _scrAddrVec1.push_back(TestChain::scrAddrC);
      _scrAddrVec1.push_back(TestChain::scrAddrD);
      _scrAddrVec1.push_back(TestChain::scrAddrE);
      _scrAddrVec1.push_back(TestChain::scrAddrF);

      vector<string> walletRegIDs;
      walletRegIDs.push_back(
         wallet1.registerAddresses(_scrAddrVec1, false));

      //wait on registration ack
      pCallback->waitOnManySignals(BDMAction_Refresh, walletRegIDs);

      //go online
      bdvObj->goOnline();
      pCallback->waitOnSignal(BDMAction_Ready);

      //balance fetching routine
      vector<string> walletIDs = { wallet1.walletID() };
      auto getBalances = [bdvObj, walletIDs](void)->CombinedBalances
      {
         auto promPtr = make_shared<promise<map<string, CombinedBalances>>>();
         auto fut = promPtr->get_future();
         auto balLbd = [promPtr](
            ReturnMessage<map<string, CombinedBalances>> combBal)->void
         {
            promPtr->set_value(combBal.get());
         };

         bdvObj->getCombinedBalances(walletIDs, balLbd);
         auto&& balMap = fut.get();

         if (balMap.size() != 1)
            throw runtime_error("unexpected balance map size");

         return balMap.begin()->second;
      };

      //check balances before pushing zc
      auto&& combineBalances = getBalances();
      EXPECT_EQ(combineBalances.addressBalances_.size(), 6);

      {
         auto iterA = combineBalances.addressBalances_.find(TestChain::scrAddrA);
         ASSERT_NE(iterA, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterA->second.size(), 3);
         EXPECT_EQ(iterA->second[0], 50 * COIN);

         auto iterB = combineBalances.addressBalances_.find(TestChain::scrAddrB);
         ASSERT_NE(iterB, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterB->second.size(), 3);
         EXPECT_EQ(iterB->second[0], 70 * COIN);

         auto iterC = combineBalances.addressBalances_.find(TestChain::scrAddrC);
         ASSERT_NE(iterC, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterC->second.size(), 3);
         EXPECT_EQ(iterC->second[0], 20 * COIN);

         auto iterD = combineBalances.addressBalances_.find(TestChain::scrAddrD);
         ASSERT_NE(iterD, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterD->second.size(), 3);
         EXPECT_EQ(iterD->second[0], 65 * COIN);

         auto iterE = combineBalances.addressBalances_.find(TestChain::scrAddrE);
         ASSERT_NE(iterE, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterE->second.size(), 3);
         EXPECT_EQ(iterE->second[0], 30 * COIN);

         auto iterF = combineBalances.addressBalances_.find(TestChain::scrAddrF);
         ASSERT_NE(iterF, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterF->second.size(), 3);
         EXPECT_EQ(iterF->second[0], 5 * COIN);
      }
   
      //instantiate resolver feed overloaded object
      auto feed = make_shared<ResolverUtils::TestResolverFeed>();
      feed->addPrivKey(TestChain::privKeyAddrB);
      feed->addPrivKey(TestChain::privKeyAddrC);
      feed->addPrivKey(TestChain::privKeyAddrD);
      feed->addPrivKey(TestChain::privKeyAddrE);
      feed->addPrivKey(TestChain::privKeyAddrF);

      //grab utxos for scrAddrB & scrAddrC
      auto promUtxo = make_shared<promise<vector<UTXO>>>();
      auto futUtxo = promUtxo->get_future();
      auto getUtxoLbd = [promUtxo](ReturnMessage<vector<UTXO>> msg)->void
      {
         promUtxo->set_value(msg.get());
      };

      wallet1.getSpendableTxOutListForValue(UINT64_MAX, getUtxoLbd);
      vector<UTXO> utxosB, utxosC;
      {
         auto&& utxoVec = futUtxo.get();
         for (auto& utxo : utxoVec)
         {
            if (utxo.getRecipientScrAddr() == TestChain::scrAddrB)
               utxosB.push_back(utxo);
            else if (utxo.getRecipientScrAddr() == TestChain::scrAddrC)
               utxosC.push_back(utxo);
         }
      }

      ASSERT_FALSE(utxosB.empty());
      ASSERT_FALSE(utxosC.empty());

      /*create the transactions*/

      //grab utxo from raw tx
      auto getUtxoFromRawTx = [](BinaryData& rawTx, unsigned id)->UTXO
      {
         Tx tx(rawTx);
         if (id > tx.getNumTxOut())
            throw runtime_error("invalid txout count");

         auto&& txOut = tx.getTxOutCopy(id);

         UTXO utxo;
         utxo.unserializeRaw(txOut.serialize());
         utxo.txOutIndex_ = id;
         utxo.txHash_ = tx.getThisHash();

         return utxo;
      };

      BinaryData rawTx1_B;
      {
         //20 from B, 5 to A, change to D
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxosB[0]);
         signer.addSpender(spender);

         auto recA = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrA.getSliceCopy(1, 20), 5 * COIN);
         signer.addRecipient(recA);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrD.getSliceCopy(1, 20), 
            spender->getValue() - recA->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx1_B = signer.serializeSignedTx();
      }

      BinaryData rawTx1_C;
      {
         //20 from C, 5 to E, change to C
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxosC[0]);
         signer.addSpender(spender);

         auto recE = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrE.getSliceCopy(1, 20), 5 * COIN);
         signer.addRecipient(recE);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrC.getSliceCopy(1, 20), 
            spender->getValue() - recE->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx1_C = signer.serializeSignedTx();
      }

      BinaryData rawTx2;
      {
         auto utxoD = getUtxoFromRawTx(rawTx1_B, 1);

         //15 from D, 10 to E, change to F
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxoD);
         signer.addSpender(spender);

         auto recE = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrE.getSliceCopy(1, 20), 10 * COIN);
         signer.addRecipient(recE);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrF.getSliceCopy(1, 20), 
            spender->getValue() - recE->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx2 = signer.serializeSignedTx();
      }

      BinaryData rawTx3;
      {
         auto utxoD = getUtxoFromRawTx(rawTx1_B, 1);

         //15 from D, 10 to E, change to A
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxoD);
         signer.addSpender(spender);

         auto recE = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrE.getSliceCopy(1, 20), 10 * COIN);
         signer.addRecipient(recE);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrA.getSliceCopy(1, 20), 
            spender->getValue() - recE->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx3 = signer.serializeSignedTx();
      }
      
      Tx tx1_B(rawTx1_B);
      Tx tx1_C(rawTx1_C);
      Tx tx2(rawTx2);
      Tx tx3(rawTx3);

      {
         set<BinaryData> txHashes;
         txHashes.insert(tx1_B.getThisHash());

         set<BinaryData> scrAddrSet;
         scrAddrSet.insert(TestChain::scrAddrA);
         scrAddrSet.insert(TestChain::scrAddrB);
         scrAddrSet.insert(TestChain::scrAddrD);

         //push the first zc
         auto broadcastId1 = bdvObj->broadcastZC(rawTx1_B);

         //wait on notification
         pCallback->waitOnZc(txHashes, scrAddrSet, broadcastId1);
      }
         
      //batch push all tx
      auto broadcastId1 = bdvObj->broadcastZC({ rawTx1_B, rawTx1_C, rawTx2, rawTx3 });
      
      set<BinaryData> txHashes;
      txHashes.insert(tx1_C.getThisHash());
      txHashes.insert(tx2.getThisHash());
      txHashes.insert(tx3.getThisHash());

      set<BinaryData> scrAddrSet;
      scrAddrSet.insert(TestChain::scrAddrC);
      scrAddrSet.insert(TestChain::scrAddrD);
      scrAddrSet.insert(TestChain::scrAddrE);
      scrAddrSet.insert(TestChain::scrAddrF);

      //wait on zc error for conflicting child
      pCallback->waitOnError(
         tx3.getThisHash(), ArmoryErrorCodes::ZcBroadcast_VerifyRejected, broadcastId1);

      //wait on zc notifs
      pCallback->waitOnZc(txHashes, scrAddrSet, broadcastId1);

      //check balances
      combineBalances = getBalances();
      EXPECT_EQ(combineBalances.addressBalances_.size(), 6);

      {
         auto iterA = combineBalances.addressBalances_.find(TestChain::scrAddrA);
         ASSERT_NE(iterA, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterA->second.size(), 3);
         EXPECT_EQ(iterA->second[0], 55 * COIN);

         auto iterB = combineBalances.addressBalances_.find(TestChain::scrAddrB);
         ASSERT_NE(iterB, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterB->second.size(), 3);
         EXPECT_EQ(iterB->second[0], 50 * COIN);

         auto iterC = combineBalances.addressBalances_.find(TestChain::scrAddrC);
         ASSERT_NE(iterC, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterC->second.size(), 3);
         EXPECT_EQ(iterC->second[0], 15 * COIN);

         auto iterD = combineBalances.addressBalances_.find(TestChain::scrAddrD);
         ASSERT_NE(iterD, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterD->second.size(), 3);
         EXPECT_EQ(iterD->second[0], 65 * COIN);

         auto iterE = combineBalances.addressBalances_.find(TestChain::scrAddrE);
         ASSERT_NE(iterE, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterE->second.size(), 3);
         EXPECT_EQ(iterE->second[0], 45 * COIN);

         auto iterF = combineBalances.addressBalances_.find(TestChain::scrAddrF);
         ASSERT_NE(iterF, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterF->second.size(), 3);
         EXPECT_EQ(iterF->second[0], 10 * COIN);
      }
   }

   //cleanup
   auto&& bdvObj2 = AsyncClient::BlockDataViewer::getNewBDV(
      "127.0.0.1", NetworkSettings::listenPort(), ArmoryConfig::getDataDir(),
      authPeersPassLbd_, NetworkSettings::ephemeralPeers(), true, nullptr);
   bdvObj2->addPublicKey(serverPubkey);
   bdvObj2->connectToRemote();

   bdvObj2->shutdown(NetworkSettings::cookie());
   WebSocketServer::waitOnShutdown();

   EXPECT_EQ(theBDMt_->bdm()->zeroConfCont()->getMatcherMapSize(), 0);

   delete theBDMt_;
   theBDMt_ = nullptr;
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_Supernode_WebSocket, BatchZcChain_ConflictingChildren_AlreadyInChain2)
{
   TestUtils::setBlocks({ "0", "1", "2", "3", "4", "5" }, blk0dat_);
   WebSocketServer::initAuthPeers(authPeersPassLbd_);
   WebSocketServer::start(theBDMt_, true);
   auto&& serverPubkey = WebSocketServer::getPublicKey();
   theBDMt_->start(DBSettings::initMode());

   {
      auto pCallback = make_shared<DBTestUtils::UTCallback>();
      auto&& bdvObj = AsyncClient::BlockDataViewer::getNewBDV(
         "127.0.0.1", NetworkSettings::listenPort(), 
         ArmoryConfig::getDataDir(),
         authPeersPassLbd_, 
         NetworkSettings::ephemeralPeers(), true, //public server
         pCallback);
      bdvObj->addPublicKey(serverPubkey);
      bdvObj->connectToRemote();
      bdvObj->registerWithDB(BitcoinSettings::getMagicBytes());

      auto&& wallet1 = bdvObj->instantiateWallet("wallet1");

      vector<BinaryData> _scrAddrVec1;
      _scrAddrVec1.push_back(TestChain::scrAddrA);
      _scrAddrVec1.push_back(TestChain::scrAddrB);
      _scrAddrVec1.push_back(TestChain::scrAddrC);
      _scrAddrVec1.push_back(TestChain::scrAddrD);
      _scrAddrVec1.push_back(TestChain::scrAddrE);
      _scrAddrVec1.push_back(TestChain::scrAddrF);

      vector<string> walletRegIDs;
      walletRegIDs.push_back(
         wallet1.registerAddresses(_scrAddrVec1, false));

      //wait on registration ack
      pCallback->waitOnManySignals(BDMAction_Refresh, walletRegIDs);

      //go online
      bdvObj->goOnline();
      pCallback->waitOnSignal(BDMAction_Ready);

      //balance fetching routine
      vector<string> walletIDs = { wallet1.walletID() };
      auto getBalances = [bdvObj, walletIDs](void)->CombinedBalances
      {
         auto promPtr = make_shared<promise<map<string, CombinedBalances>>>();
         auto fut = promPtr->get_future();
         auto balLbd = [promPtr](
            ReturnMessage<map<string, CombinedBalances>> combBal)->void
         {
            promPtr->set_value(combBal.get());
         };

         bdvObj->getCombinedBalances(walletIDs, balLbd);
         auto&& balMap = fut.get();

         if (balMap.size() != 1)
            throw runtime_error("unexpected balance map size");

         return balMap.begin()->second;
      };

      //check balances before pushing zc
      auto&& combineBalances = getBalances();
      EXPECT_EQ(combineBalances.addressBalances_.size(), 6);

      {
         auto iterA = combineBalances.addressBalances_.find(TestChain::scrAddrA);
         ASSERT_NE(iterA, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterA->second.size(), 3);
         EXPECT_EQ(iterA->second[0], 50 * COIN);

         auto iterB = combineBalances.addressBalances_.find(TestChain::scrAddrB);
         ASSERT_NE(iterB, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterB->second.size(), 3);
         EXPECT_EQ(iterB->second[0], 70 * COIN);

         auto iterC = combineBalances.addressBalances_.find(TestChain::scrAddrC);
         ASSERT_NE(iterC, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterC->second.size(), 3);
         EXPECT_EQ(iterC->second[0], 20 * COIN);

         auto iterD = combineBalances.addressBalances_.find(TestChain::scrAddrD);
         ASSERT_NE(iterD, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterD->second.size(), 3);
         EXPECT_EQ(iterD->second[0], 65 * COIN);

         auto iterE = combineBalances.addressBalances_.find(TestChain::scrAddrE);
         ASSERT_NE(iterE, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterE->second.size(), 3);
         EXPECT_EQ(iterE->second[0], 30 * COIN);

         auto iterF = combineBalances.addressBalances_.find(TestChain::scrAddrF);
         ASSERT_NE(iterF, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterF->second.size(), 3);
         EXPECT_EQ(iterF->second[0], 5 * COIN);
      }
   
      //instantiate resolver feed overloaded object
      auto feed = make_shared<ResolverUtils::TestResolverFeed>();
      feed->addPrivKey(TestChain::privKeyAddrB);
      feed->addPrivKey(TestChain::privKeyAddrC);
      feed->addPrivKey(TestChain::privKeyAddrD);
      feed->addPrivKey(TestChain::privKeyAddrE);
      feed->addPrivKey(TestChain::privKeyAddrF);

      //grab utxos for scrAddrB & scrAddrC
      auto promUtxo = make_shared<promise<vector<UTXO>>>();
      auto futUtxo = promUtxo->get_future();
      auto getUtxoLbd = [promUtxo](ReturnMessage<vector<UTXO>> msg)->void
      {
         promUtxo->set_value(msg.get());
      };

      wallet1.getSpendableTxOutListForValue(UINT64_MAX, getUtxoLbd);
      vector<UTXO> utxosB, utxosC;
      {
         auto&& utxoVec = futUtxo.get();
         for (auto& utxo : utxoVec)
         {
            if (utxo.getRecipientScrAddr() == TestChain::scrAddrB)
               utxosB.push_back(utxo);
            else if (utxo.getRecipientScrAddr() == TestChain::scrAddrC)
               utxosC.push_back(utxo);
         }
      }

      ASSERT_FALSE(utxosB.empty());
      ASSERT_FALSE(utxosC.empty());

      /*create the transactions*/

      //grab utxo from raw tx
      auto getUtxoFromRawTx = [](BinaryData& rawTx, unsigned id)->UTXO
      {
         Tx tx(rawTx);
         if (id > tx.getNumTxOut())
            throw runtime_error("invalid txout count");

         auto&& txOut = tx.getTxOutCopy(id);

         UTXO utxo;
         utxo.unserializeRaw(txOut.serialize());
         utxo.txOutIndex_ = id;
         utxo.txHash_ = tx.getThisHash();

         return utxo;
      };

      BinaryData rawTx1_B;
      {
         //20 from B, 5 to A, change to D
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxosB[0]);
         signer.addSpender(spender);

         auto recA = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrA.getSliceCopy(1, 20), 5 * COIN);
         signer.addRecipient(recA);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrD.getSliceCopy(1, 20), 
            spender->getValue() - recA->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx1_B = signer.serializeSignedTx();
      }

      BinaryData rawTx1_C;
      {
         //20 from C, 5 to E, change to C
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxosC[0]);
         signer.addSpender(spender);

         auto recE = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrE.getSliceCopy(1, 20), 5 * COIN);
         signer.addRecipient(recE);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrC.getSliceCopy(1, 20), 
            spender->getValue() - recE->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx1_C = signer.serializeSignedTx();
      }

      BinaryData rawTx2;
      {
         auto utxoD = getUtxoFromRawTx(rawTx1_B, 1);

         //15 from D, 10 to E, change to F
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxoD);
         signer.addSpender(spender);

         auto recE = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrE.getSliceCopy(1, 20), 10 * COIN);
         signer.addRecipient(recE);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrF.getSliceCopy(1, 20), 
            spender->getValue() - recE->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx2 = signer.serializeSignedTx();
      }

      BinaryData rawTx3;
      {
         auto utxoD = getUtxoFromRawTx(rawTx1_B, 1);

         //15 from D, 10 to E, change to A
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxoD);
         signer.addSpender(spender);

         auto recE = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrE.getSliceCopy(1, 20), 10 * COIN);
         signer.addRecipient(recE);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrA.getSliceCopy(1, 20), 
            spender->getValue() - recE->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx3 = signer.serializeSignedTx();
      }
      
      Tx tx1_B(rawTx1_B);
      Tx tx1_C(rawTx1_C);
      Tx tx2(rawTx2);
      Tx tx3(rawTx3);

      {
         set<BinaryData> txHashes;
         txHashes.insert(tx1_B.getThisHash());
         txHashes.insert(tx2.getThisHash());

         set<BinaryData> scrAddrSet;
         scrAddrSet.insert(TestChain::scrAddrA);
         scrAddrSet.insert(TestChain::scrAddrB);
         scrAddrSet.insert(TestChain::scrAddrD);
         scrAddrSet.insert(TestChain::scrAddrE);
         scrAddrSet.insert(TestChain::scrAddrF);

         //push the first zc and its child through the node
         nodePtr_->pushZC({ {rawTx1_B, 0}, {rawTx2, 0} }, false);

         //wait on notification
         pCallback->waitOnZc(txHashes, scrAddrSet, "");
      }
         
      //batch push first zc (already in chain), C (unrelated) 
      //and tx3 (child of first, mempool conflict with tx2)
      auto broadcastId1 = bdvObj->broadcastZC({ rawTx1_B, rawTx1_C, rawTx3 });
      
      set<BinaryData> txHashes;
      txHashes.insert(tx1_C.getThisHash());

      set<BinaryData> scrAddrSet;
      scrAddrSet.insert(TestChain::scrAddrC);
      scrAddrSet.insert(TestChain::scrAddrE);

      //wait on zc error for conflicting child
      pCallback->waitOnError(
         tx3.getThisHash(), ArmoryErrorCodes::ZcBroadcast_VerifyRejected, broadcastId1);

      //wait on zc notifs
      pCallback->waitOnZc(txHashes, scrAddrSet, broadcastId1);

      //check balances
      combineBalances = getBalances();
      EXPECT_EQ(combineBalances.addressBalances_.size(), 6);

      {
         auto iterA = combineBalances.addressBalances_.find(TestChain::scrAddrA);
         ASSERT_NE(iterA, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterA->second.size(), 3);
         EXPECT_EQ(iterA->second[0], 55 * COIN);

         auto iterB = combineBalances.addressBalances_.find(TestChain::scrAddrB);
         ASSERT_NE(iterB, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterB->second.size(), 3);
         EXPECT_EQ(iterB->second[0], 50 * COIN);

         auto iterC = combineBalances.addressBalances_.find(TestChain::scrAddrC);
         ASSERT_NE(iterC, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterC->second.size(), 3);
         EXPECT_EQ(iterC->second[0], 15 * COIN);

         auto iterD = combineBalances.addressBalances_.find(TestChain::scrAddrD);
         ASSERT_NE(iterD, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterD->second.size(), 3);
         EXPECT_EQ(iterD->second[0], 65 * COIN);

         auto iterE = combineBalances.addressBalances_.find(TestChain::scrAddrE);
         ASSERT_NE(iterE, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterE->second.size(), 3);
         EXPECT_EQ(iterE->second[0], 45 * COIN);

         auto iterF = combineBalances.addressBalances_.find(TestChain::scrAddrF);
         ASSERT_NE(iterF, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterF->second.size(), 3);
         EXPECT_EQ(iterF->second[0], 10 * COIN);
      }
   }

   //cleanup
   auto&& bdvObj2 = AsyncClient::BlockDataViewer::getNewBDV(
      "127.0.0.1", NetworkSettings::listenPort(), ArmoryConfig::getDataDir(),
      authPeersPassLbd_, NetworkSettings::ephemeralPeers(), true, nullptr);
   bdvObj2->addPublicKey(serverPubkey);
   bdvObj2->connectToRemote();

   bdvObj2->shutdown(NetworkSettings::cookie());
   WebSocketServer::waitOnShutdown();

   EXPECT_EQ(theBDMt_->bdm()->zeroConfCont()->getMatcherMapSize(), 0);

   delete theBDMt_;
   theBDMt_ = nullptr;
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_Supernode_WebSocket, BatchZcChain_ConflictingChildren_AlreadyInChain3)
{
   TestUtils::setBlocks({ "0", "1", "2", "3", "4", "5" }, blk0dat_);
   WebSocketServer::initAuthPeers(authPeersPassLbd_);
   WebSocketServer::start(theBDMt_, true);
   auto&& serverPubkey = WebSocketServer::getPublicKey();
   theBDMt_->start(DBSettings::initMode());

   {
      auto pCallback = make_shared<DBTestUtils::UTCallback>();
      auto&& bdvObj = AsyncClient::BlockDataViewer::getNewBDV(
         "127.0.0.1", NetworkSettings::listenPort(), 
         ArmoryConfig::getDataDir(),
         authPeersPassLbd_, 
         NetworkSettings::ephemeralPeers(), true, //public server
         pCallback);
      bdvObj->addPublicKey(serverPubkey);
      bdvObj->connectToRemote();
      bdvObj->registerWithDB(BitcoinSettings::getMagicBytes());

      auto&& wallet1 = bdvObj->instantiateWallet("wallet1");

      vector<BinaryData> _scrAddrVec1;
      _scrAddrVec1.push_back(TestChain::scrAddrA);
      _scrAddrVec1.push_back(TestChain::scrAddrB);
      _scrAddrVec1.push_back(TestChain::scrAddrC);
      _scrAddrVec1.push_back(TestChain::scrAddrD);
      _scrAddrVec1.push_back(TestChain::scrAddrE);
      _scrAddrVec1.push_back(TestChain::scrAddrF);

      vector<string> walletRegIDs;
      walletRegIDs.push_back(
         wallet1.registerAddresses(_scrAddrVec1, false));

      //wait on registration ack
      pCallback->waitOnManySignals(BDMAction_Refresh, walletRegIDs);

      //go online
      bdvObj->goOnline();
      pCallback->waitOnSignal(BDMAction_Ready);

      //balance fetching routine
      vector<string> walletIDs = { wallet1.walletID() };
      auto getBalances = [bdvObj, walletIDs](void)->CombinedBalances
      {
         auto promPtr = make_shared<promise<map<string, CombinedBalances>>>();
         auto fut = promPtr->get_future();
         auto balLbd = [promPtr](
            ReturnMessage<map<string, CombinedBalances>> combBal)->void
         {
            promPtr->set_value(combBal.get());
         };

         bdvObj->getCombinedBalances(walletIDs, balLbd);
         auto&& balMap = fut.get();

         if (balMap.size() != 1)
            throw runtime_error("unexpected balance map size");

         return balMap.begin()->second;
      };

      //check balances before pushing zc
      auto&& combineBalances = getBalances();
      EXPECT_EQ(combineBalances.addressBalances_.size(), 6);

      {
         auto iterA = combineBalances.addressBalances_.find(TestChain::scrAddrA);
         ASSERT_NE(iterA, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterA->second.size(), 3);
         EXPECT_EQ(iterA->second[0], 50 * COIN);

         auto iterB = combineBalances.addressBalances_.find(TestChain::scrAddrB);
         ASSERT_NE(iterB, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterB->second.size(), 3);
         EXPECT_EQ(iterB->second[0], 70 * COIN);

         auto iterC = combineBalances.addressBalances_.find(TestChain::scrAddrC);
         ASSERT_NE(iterC, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterC->second.size(), 3);
         EXPECT_EQ(iterC->second[0], 20 * COIN);

         auto iterD = combineBalances.addressBalances_.find(TestChain::scrAddrD);
         ASSERT_NE(iterD, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterD->second.size(), 3);
         EXPECT_EQ(iterD->second[0], 65 * COIN);

         auto iterE = combineBalances.addressBalances_.find(TestChain::scrAddrE);
         ASSERT_NE(iterE, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterE->second.size(), 3);
         EXPECT_EQ(iterE->second[0], 30 * COIN);

         auto iterF = combineBalances.addressBalances_.find(TestChain::scrAddrF);
         ASSERT_NE(iterF, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterF->second.size(), 3);
         EXPECT_EQ(iterF->second[0], 5 * COIN);
      }
   
      //instantiate resolver feed overloaded object
      auto feed = make_shared<ResolverUtils::TestResolverFeed>();
      feed->addPrivKey(TestChain::privKeyAddrB);
      feed->addPrivKey(TestChain::privKeyAddrC);
      feed->addPrivKey(TestChain::privKeyAddrD);
      feed->addPrivKey(TestChain::privKeyAddrE);
      feed->addPrivKey(TestChain::privKeyAddrF);

      //grab utxos for scrAddrB & scrAddrC
      auto promUtxo = make_shared<promise<vector<UTXO>>>();
      auto futUtxo = promUtxo->get_future();
      auto getUtxoLbd = [promUtxo](ReturnMessage<vector<UTXO>> msg)->void
      {
         promUtxo->set_value(msg.get());
      };

      wallet1.getSpendableTxOutListForValue(UINT64_MAX, getUtxoLbd);
      vector<UTXO> utxosB, utxosC;
      {
         auto&& utxoVec = futUtxo.get();
         for (auto& utxo : utxoVec)
         {
            if (utxo.getRecipientScrAddr() == TestChain::scrAddrB)
               utxosB.push_back(utxo);
            else if (utxo.getRecipientScrAddr() == TestChain::scrAddrC)
               utxosC.push_back(utxo);
         }
      }

      ASSERT_FALSE(utxosB.empty());
      ASSERT_FALSE(utxosC.empty());

      /*create the transactions*/

      //grab utxo from raw tx
      auto getUtxoFromRawTx = [](BinaryData& rawTx, unsigned id)->UTXO
      {
         Tx tx(rawTx);
         if (id > tx.getNumTxOut())
            throw runtime_error("invalid txout count");

         auto&& txOut = tx.getTxOutCopy(id);

         UTXO utxo;
         utxo.unserializeRaw(txOut.serialize());
         utxo.txOutIndex_ = id;
         utxo.txHash_ = tx.getThisHash();

         return utxo;
      };

      BinaryData rawTx1_B;
      {
         //20 from B, 5 to A, change to D
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxosB[0]);
         signer.addSpender(spender);

         auto recA = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrA.getSliceCopy(1, 20), 5 * COIN);
         signer.addRecipient(recA);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrD.getSliceCopy(1, 20), 
            spender->getValue() - recA->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx1_B = signer.serializeSignedTx();
      }

      BinaryData rawTx1_C;
      {
         //20 from C, 5 to E, change to C
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxosC[0]);
         signer.addSpender(spender);

         auto recE = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrE.getSliceCopy(1, 20), 5 * COIN);
         signer.addRecipient(recE);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrC.getSliceCopy(1, 20), 
            spender->getValue() - recE->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx1_C = signer.serializeSignedTx();
      }

      BinaryData rawTx2;
      {
         auto utxoD = getUtxoFromRawTx(rawTx1_B, 1);

         //15 from D, 10 to E, change to F
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxoD);
         signer.addSpender(spender);

         auto recE = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrE.getSliceCopy(1, 20), 10 * COIN);
         signer.addRecipient(recE);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrF.getSliceCopy(1, 20), 
            spender->getValue() - recE->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx2 = signer.serializeSignedTx();
      }

      BinaryData rawTx3;
      {
         auto utxoD = getUtxoFromRawTx(rawTx1_B, 1);
         auto utxoE = getUtxoFromRawTx(rawTx1_C, 0);

         //15+5 from D & E, 10 to E, change to A
         Signer signer;

         auto spender1 = make_shared<ScriptSpender>(utxoD);
         auto spender2 = make_shared<ScriptSpender>(utxoE);
         signer.addSpender(spender1);
         signer.addSpender(spender2);

         auto recE = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrE.getSliceCopy(1, 20), 10 * COIN);
         signer.addRecipient(recE);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrA.getSliceCopy(1, 20), 10 * COIN);
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx3 = signer.serializeSignedTx();
      }
      
      Tx tx1_B(rawTx1_B);
      Tx tx1_C(rawTx1_C);
      Tx tx2(rawTx2);
      Tx tx3(rawTx3);

      {
         set<BinaryData> txHashes;
         txHashes.insert(tx1_B.getThisHash());
         txHashes.insert(tx2.getThisHash());

         set<BinaryData> scrAddrSet;
         scrAddrSet.insert(TestChain::scrAddrA);
         scrAddrSet.insert(TestChain::scrAddrB);
         scrAddrSet.insert(TestChain::scrAddrD);
         scrAddrSet.insert(TestChain::scrAddrE);
         scrAddrSet.insert(TestChain::scrAddrF);

         //push the first zc and its child
         auto broadcastId1 = bdvObj->broadcastZC({ rawTx1_B, rawTx2 });

         //wait on notification
         pCallback->waitOnZc(txHashes, scrAddrSet, broadcastId1);
      }
         
      //batch push first zc (already in chain), C (unrelated) 
      //and tx3 (child of first & C, mempool conflict with tx2 on utxo from first)
      auto broadcastId1 = bdvObj->broadcastZC({ rawTx1_B, rawTx1_C, rawTx3 });
      
      set<BinaryData> txHashes;
      txHashes.insert(tx1_C.getThisHash());

      set<BinaryData> scrAddrSet;
      scrAddrSet.insert(TestChain::scrAddrC);
      scrAddrSet.insert(TestChain::scrAddrE);

      //wait on zc error for conflicting child
      pCallback->waitOnError(
         tx3.getThisHash(), ArmoryErrorCodes::ZcBroadcast_VerifyRejected, broadcastId1);

      //wait on zc notifs
      pCallback->waitOnZc(txHashes, scrAddrSet, broadcastId1);

      //check balances
      combineBalances = getBalances();
      EXPECT_EQ(combineBalances.addressBalances_.size(), 6);

      {
         auto iterA = combineBalances.addressBalances_.find(TestChain::scrAddrA);
         ASSERT_NE(iterA, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterA->second.size(), 3);
         EXPECT_EQ(iterA->second[0], 55 * COIN);

         auto iterB = combineBalances.addressBalances_.find(TestChain::scrAddrB);
         ASSERT_NE(iterB, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterB->second.size(), 3);
         EXPECT_EQ(iterB->second[0], 50 * COIN);

         auto iterC = combineBalances.addressBalances_.find(TestChain::scrAddrC);
         ASSERT_NE(iterC, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterC->second.size(), 3);
         EXPECT_EQ(iterC->second[0], 15 * COIN);

         auto iterD = combineBalances.addressBalances_.find(TestChain::scrAddrD);
         ASSERT_NE(iterD, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterD->second.size(), 3);
         EXPECT_EQ(iterD->second[0], 65 * COIN);

         auto iterE = combineBalances.addressBalances_.find(TestChain::scrAddrE);
         ASSERT_NE(iterE, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterE->second.size(), 3);
         EXPECT_EQ(iterE->second[0], 45 * COIN);

         auto iterF = combineBalances.addressBalances_.find(TestChain::scrAddrF);
         ASSERT_NE(iterF, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterF->second.size(), 3);
         EXPECT_EQ(iterF->second[0], 10 * COIN);
      }
   }

   //cleanup
   auto&& bdvObj2 = AsyncClient::BlockDataViewer::getNewBDV(
      "127.0.0.1", NetworkSettings::listenPort(), ArmoryConfig::getDataDir(),
      authPeersPassLbd_, NetworkSettings::ephemeralPeers(), true, nullptr);
   bdvObj2->addPublicKey(serverPubkey);
   bdvObj2->connectToRemote();

   bdvObj2->shutdown(NetworkSettings::cookie());
   WebSocketServer::waitOnShutdown();

   EXPECT_EQ(theBDMt_->bdm()->zeroConfCont()->getMatcherMapSize(), 0);

   delete theBDMt_;
   theBDMt_ = nullptr;
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_Supernode_WebSocket, BroadcastAlreadyMinedTx)
{
   TestUtils::setBlocks({ "0", "1", "2", "3", "4", "5" }, blk0dat_);
   WebSocketServer::initAuthPeers(authPeersPassLbd_);
   WebSocketServer::start(theBDMt_, true);
   auto&& serverPubkey = WebSocketServer::getPublicKey();
   theBDMt_->start(DBSettings::initMode());

   {
      auto pCallback = make_shared<DBTestUtils::UTCallback>();
      auto&& bdvObj = AsyncClient::BlockDataViewer::getNewBDV(
         "127.0.0.1", NetworkSettings::listenPort(), 
         ArmoryConfig::getDataDir(),
         authPeersPassLbd_, 
         NetworkSettings::ephemeralPeers(), true, //public server
         pCallback);
      bdvObj->addPublicKey(serverPubkey);
      bdvObj->connectToRemote();
      bdvObj->registerWithDB(BitcoinSettings::getMagicBytes());

      auto&& wallet1 = bdvObj->instantiateWallet("wallet1");

      vector<BinaryData> _scrAddrVec1;
      _scrAddrVec1.push_back(TestChain::scrAddrA);
      _scrAddrVec1.push_back(TestChain::scrAddrB);
      _scrAddrVec1.push_back(TestChain::scrAddrC);
      _scrAddrVec1.push_back(TestChain::scrAddrD);
      _scrAddrVec1.push_back(TestChain::scrAddrE);
      _scrAddrVec1.push_back(TestChain::scrAddrF);

      vector<string> walletRegIDs;
      walletRegIDs.push_back(
         wallet1.registerAddresses(_scrAddrVec1, false));

      //wait on registration ack
      pCallback->waitOnManySignals(BDMAction_Refresh, walletRegIDs);

      //go online
      bdvObj->goOnline();
      pCallback->waitOnSignal(BDMAction_Ready);

      //grab a mined tx with unspent outputs
      auto&& ZC1 = TestUtils::getTx(5, 2); //block 5, tx 2
      auto&& ZChash1 = BtcUtils::getHash256(ZC1);

      //and one with spent outputs
      auto&& ZC2 = TestUtils::getTx(2, 1); //block 5, tx 2
      auto&& ZChash2 = BtcUtils::getHash256(ZC2);

      //try and broadcast both
      auto broadcastId1 = bdvObj->broadcastZC({ZC1, ZC2});

      //wait on zc errors
      pCallback->waitOnError(ZChash1, 
         ArmoryErrorCodes::ZcBroadcast_AlreadyInChain, broadcastId1);
      
      pCallback->waitOnError(ZChash2, 
         ArmoryErrorCodes::ZcBroadcast_AlreadyInChain, broadcastId1);
   }

   //cleanup
   auto&& bdvObj2 = AsyncClient::BlockDataViewer::getNewBDV(
      "127.0.0.1", NetworkSettings::listenPort(), ArmoryConfig::getDataDir(),
      authPeersPassLbd_, NetworkSettings::ephemeralPeers(), true, nullptr);
   bdvObj2->addPublicKey(serverPubkey);
   bdvObj2->connectToRemote();

   bdvObj2->shutdown(NetworkSettings::cookie());
   WebSocketServer::waitOnShutdown();

   delete theBDMt_;
   theBDMt_ = nullptr;
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_Supernode_WebSocket, BroadcastSameZC_ManyThreads)
{
   struct WSClient
   {
      shared_ptr<AsyncClient::BlockDataViewer> bdvPtr_;
      AsyncClient::BtcWallet wlt_;
      shared_ptr<DBTestUtils::UTCallback> callbackPtr_;

      WSClient(
         shared_ptr<AsyncClient::BlockDataViewer> bdvPtr, 
         AsyncClient::BtcWallet& wlt,
         shared_ptr<DBTestUtils::UTCallback> callbackPtr) :
         bdvPtr_(bdvPtr), wlt_(move(wlt)), callbackPtr_(callbackPtr)
      {}
   };

   TestUtils::setBlocks({ "0", "1", "2", "3", "4", "5" }, blk0dat_);
   WebSocketServer::initAuthPeers(authPeersPassLbd_);
   WebSocketServer::start(theBDMt_, true);
   auto&& serverPubkey = WebSocketServer::getPublicKey();
   theBDMt_->start(DBSettings::initMode());

   //create BDV lambda
   auto setupBDV = [this, &serverPubkey](void)->shared_ptr<WSClient>
   {
      auto pCallback = make_shared<DBTestUtils::UTCallback>();
      auto&& bdvObj = AsyncClient::BlockDataViewer::getNewBDV(
         "127.0.0.1", NetworkSettings::listenPort(), 
         ArmoryConfig::getDataDir(),
         authPeersPassLbd_, 
         NetworkSettings::ephemeralPeers(), true, //public server
         pCallback);
      bdvObj->addPublicKey(serverPubkey);
      bdvObj->connectToRemote();
      bdvObj->registerWithDB(BitcoinSettings::getMagicBytes());

      auto&& wallet1 = bdvObj->instantiateWallet("wallet1");

      vector<BinaryData> _scrAddrVec1;
      _scrAddrVec1.push_back(TestChain::scrAddrA);
      _scrAddrVec1.push_back(TestChain::scrAddrB);
      _scrAddrVec1.push_back(TestChain::scrAddrC);
      _scrAddrVec1.push_back(TestChain::scrAddrD);
      _scrAddrVec1.push_back(TestChain::scrAddrE);
      _scrAddrVec1.push_back(TestChain::scrAddrF);

      vector<string> walletRegIDs;
      walletRegIDs.push_back(
         wallet1.registerAddresses(_scrAddrVec1, false));

      //wait on registration ack
      pCallback->waitOnManySignals(BDMAction_Refresh, walletRegIDs);

      //go online
      bdvObj->goOnline();
      pCallback->waitOnSignal(BDMAction_Ready);

      auto client = make_shared<WSClient>(bdvObj, wallet1, pCallback);
      return client;
   };

   //create main bdv instance
   auto mainInstance = setupBDV();

   /*
   create a batch of zc with chains:
      1-2-3
      1-4 (4 conflicts with 2)
      5-6
      7
   */

   vector<BinaryData> rawTxVec, zcHashes;
   map<BinaryData, map<unsigned, UTXO>> outputMap;
   {
      //instantiate resolver feed overloaded object
      auto feed = make_shared<ResolverUtils::TestResolverFeed>();
      feed->addPrivKey(TestChain::privKeyAddrB);
      feed->addPrivKey(TestChain::privKeyAddrC);
      feed->addPrivKey(TestChain::privKeyAddrD);
      feed->addPrivKey(TestChain::privKeyAddrE);
      feed->addPrivKey(TestChain::privKeyAddrF);

      //utxo from raw tx lambda
      auto getUtxoFromRawTx = [&outputMap](BinaryData& rawTx, unsigned id)->UTXO
      {
         Tx tx(rawTx);
         if (id > tx.getNumTxOut())
            throw runtime_error("invalid txout count");

         auto&& txOut = tx.getTxOutCopy(id);

         UTXO utxo;
         utxo.unserializeRaw(txOut.serialize());
         utxo.txOutIndex_ = id;
         utxo.txHash_ = tx.getThisHash();

         auto& idMap = outputMap[utxo.txHash_];
         idMap[id] = utxo;

         return utxo;
      };

      //grab utxos for scrAddrB, scrAddrC, scrAddrE
      auto promUtxo = make_shared<promise<vector<UTXO>>>();
      auto futUtxo = promUtxo->get_future();
      auto getUtxoLbd = [promUtxo](ReturnMessage<vector<UTXO>> msg)->void
      {
         promUtxo->set_value(msg.get());
      };

      mainInstance->wlt_.getSpendableTxOutListForValue(UINT64_MAX, getUtxoLbd);
      vector<UTXO> utxosB, utxosC, utxosE;
      {
         auto&& utxoVec = futUtxo.get();
         for (auto& utxo : utxoVec)
         {
            if (utxo.getRecipientScrAddr() == TestChain::scrAddrB)
               utxosB.push_back(utxo);
            else if (utxo.getRecipientScrAddr() == TestChain::scrAddrC)
               utxosC.push_back(utxo);
            else if (utxo.getRecipientScrAddr() == TestChain::scrAddrE)
               utxosE.push_back(utxo);

            auto& idMap = outputMap[utxo.txHash_];
            idMap[utxo.txOutIndex_] = utxo;
         }
      }

      ASSERT_FALSE(utxosB.empty());
      ASSERT_FALSE(utxosC.empty());
      ASSERT_FALSE(utxosE.empty());

      /*create the transactions*/

      //1
      {
         //20 from B, 5 to A, change to D
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxosB[0]);
         signer.addSpender(spender);

         auto recA = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrA.getSliceCopy(1, 20), 5 * COIN);
         signer.addRecipient(recA);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrD.getSliceCopy(1, 20), 
            spender->getValue() - recA->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTxVec.push_back(signer.serializeSignedTx());
         Tx tx(rawTxVec.back());
         zcHashes.push_back(tx.getThisHash());
      }

      //2
      {
         auto utxoD = getUtxoFromRawTx(rawTxVec[0], 1);

         //15 from D, 10 to E, change to F
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxoD);
         signer.addSpender(spender);

         auto recE = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrE.getSliceCopy(1, 20), 10 * COIN);
         signer.addRecipient(recE);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrF.getSliceCopy(1, 20), 
            spender->getValue() - recE->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTxVec.push_back(signer.serializeSignedTx());
         Tx tx(rawTxVec.back());
         zcHashes.push_back(tx.getThisHash());
      }
      
      //3
      {
         auto utxoF = getUtxoFromRawTx(rawTxVec[1], 1);

         //5 from F, 5 to B
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxoF);
         signer.addSpender(spender);

         auto recB = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrB.getSliceCopy(1, 20), 5 * COIN);
         signer.addRecipient(recB);

         signer.setFeed(feed);
         signer.sign();
         rawTxVec.push_back(signer.serializeSignedTx());
         Tx tx(rawTxVec.back());
         zcHashes.push_back(tx.getThisHash());
      }

      //4
      {
         auto utxoA = getUtxoFromRawTx(rawTxVec[0], 1);

         //15 from D, 14 to C
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxoA);
         signer.addSpender(spender);

         auto recC = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrC.getSliceCopy(1, 20), 14 * COIN);
         signer.addRecipient(recC);

         signer.setFeed(feed);
         signer.sign();
         rawTxVec.push_back(signer.serializeSignedTx());
         Tx tx(rawTxVec.back());
         zcHashes.push_back(tx.getThisHash());
      }

      //5
      {
         //10 from C, 10 to D
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxosC[0]);
         signer.addSpender(spender);

         auto recD = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrD.getSliceCopy(1, 20), 10 * COIN);
         signer.addRecipient(recD);

         signer.setFeed(feed);
         signer.sign();
         rawTxVec.push_back(signer.serializeSignedTx());
         Tx tx(rawTxVec.back());
         zcHashes.push_back(tx.getThisHash());
      }

      //6
      {
         auto utxoD = getUtxoFromRawTx(rawTxVec[4], 0);

         //10 from D, 5 to F, change to A
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxoD);
         signer.addSpender(spender);

         auto recF = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrF.getSliceCopy(1, 20), 5 * COIN);
         signer.addRecipient(recF);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrA.getSliceCopy(1, 20), 
            spender->getValue() - recF->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTxVec.push_back(signer.serializeSignedTx());
         Tx tx(rawTxVec.back());
         zcHashes.push_back(tx.getThisHash());
      }

      //7
      {
         //20 from E, 10 to F, change to A
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxosE[0]);
         signer.addSpender(spender);

         auto recF = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrF.getSliceCopy(1, 20), 10 * COIN);
         signer.addRecipient(recF);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrA.getSliceCopy(1, 20), 
            spender->getValue() - recF->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTxVec.push_back(signer.serializeSignedTx());
         Tx tx(rawTxVec.back());
         zcHashes.push_back(tx.getThisHash());
      }      
   }

   //3 case1, 3 case2, 1 case3, 3 case4, 3 case5
   unsigned N = 13;

   //create N side instances
   vector<shared_ptr<WSClient>> sideInstances;
   for (unsigned i=0; i<N; i++)
      sideInstances.emplace_back(setupBDV());

   //get addresses for tx lambda
   auto getAddressesForRawTx = [&outputMap](const Tx& tx)->set<BinaryData>
   {
      set<BinaryData> addrSet;

      for (unsigned i=0; i<tx.getNumTxIn(); i++)
      {
         auto txin = tx.getTxInCopy(i);
         auto op = txin.getOutPoint();

         auto hashIter = outputMap.find(op.getTxHash());
         EXPECT_TRUE(hashIter != outputMap.end());

         auto idIter = hashIter->second.find(op.getTxOutIndex());
         EXPECT_TRUE(idIter != hashIter->second.end());

         auto& utxo = idIter->second;
         addrSet.insert(utxo.getRecipientScrAddr());
      }

      for (unsigned i=0; i<tx.getNumTxOut(); i++)
      {
         auto txout = tx.getTxOutCopy(i);
         addrSet.insert(txout.getScrAddressStr());
      }

      return addrSet;
   };

   set<BinaryData> mainScrAddrSet;
   set<BinaryData> mainHashes;   
   {
      vector<unsigned> zcIds = {1, 2, 3, 5, 6};
      for (auto& id : zcIds)
      {
         Tx tx(rawTxVec[id - 1]);
         mainHashes.insert(tx.getThisHash());
         auto localAddrSet = getAddressesForRawTx(tx);
         mainScrAddrSet.insert(localAddrSet.begin(), localAddrSet.end());
      }   
   }

   //case 1
   auto case1 = [&](unsigned instanceId)->void
   {
      auto instance = sideInstances[instanceId];

      //push 1-2-3
      vector<unsigned> zcIds = {1, 2, 3};

      //ids for the zc we are not broadcasting but which addresses we watch
      vector<unsigned> zcIds_skipped = {5, 6};

      vector<BinaryData> zcs;
      set<BinaryData> addrSet;
      set<BinaryData> hashSet;
      for (auto& id : zcIds)
      {
         zcs.push_back(rawTxVec[id - 1]);
         Tx tx(rawTxVec[id - 1]);
         hashSet.insert(tx.getThisHash());
         auto localAddrSet = getAddressesForRawTx(tx);
         addrSet.insert(localAddrSet.begin(), localAddrSet.end());
      }

      set<BinaryData> addrSet_skipped;
      set<BinaryData> hashSet_skipped;
      for (auto& id : zcIds_skipped)
      {
         Tx tx(rawTxVec[id - 1]);
         hashSet_skipped.insert(tx.getThisHash());
         auto localAddrSet = getAddressesForRawTx(tx);
         addrSet_skipped.insert(localAddrSet.begin(), localAddrSet.end());
      }

      auto broadcastId1 = instance->bdvPtr_->broadcastZC(zcs);

      //wait on broadcast errors
      map<BinaryData, ArmoryErrorCodes> errorMap;
      for (auto& id : zcIds)
         errorMap.emplace(zcHashes[id - 1], ArmoryErrorCodes::ZcBroadcast_AlreadyInMempool);
      instance->callbackPtr_->waitOnErrors(errorMap, broadcastId1);

      //wait on zc
      instance->callbackPtr_->waitOnZc(hashSet_skipped, addrSet_skipped, "");
      instance->callbackPtr_->waitOnZc(hashSet, addrSet, broadcastId1);
   };

   //case 2
   auto case2 = [&](unsigned instanceId)->void
   {
      auto instance = sideInstances[instanceId];

      //push 5-6
      vector<unsigned> zcIds = {5, 6};
      vector<unsigned> zcIds_skipped = {1, 2, 3};

      vector<BinaryData> zcs;
      set<BinaryData> addrSet;
      set<BinaryData> hashSet;
      for (auto& id : zcIds)
      {
         zcs.push_back(rawTxVec[id - 1]);
         Tx tx(rawTxVec[id - 1]);
         hashSet.insert(tx.getThisHash());
         auto localAddrSet = getAddressesForRawTx(tx);
         addrSet.insert(localAddrSet.begin(), localAddrSet.end());
      }   

      set<BinaryData> addrSet_skipped;
      set<BinaryData> hashSet_skipped;
      for (auto& id : zcIds_skipped)
      {
         Tx tx(rawTxVec[id - 1]);
         hashSet_skipped.insert(tx.getThisHash());
         auto localAddrSet = getAddressesForRawTx(tx);
         addrSet_skipped.insert(localAddrSet.begin(), localAddrSet.end());
      }

      auto broadcastId1 = instance->bdvPtr_->broadcastZC(zcs);

      //wait on broadcast errors
      map<BinaryData, ArmoryErrorCodes> errorMap;
      for (auto& id : zcIds)
         errorMap.emplace(zcHashes[id - 1], ArmoryErrorCodes::ZcBroadcast_AlreadyInMempool);
      instance->callbackPtr_->waitOnErrors(errorMap, broadcastId1);

      //wait on zc
      instance->callbackPtr_->waitOnZc(hashSet_skipped, addrSet_skipped, "");
      instance->callbackPtr_->waitOnZc(hashSet, addrSet, broadcastId1);
   };

   //case 3
   auto case3 = [&](unsigned instanceId)->void
   {
      auto instance = sideInstances[instanceId];

      //push 1-4 7
      auto broadcastId1 = instance->bdvPtr_->broadcastZC({
         rawTxVec[0], rawTxVec[3],
         rawTxVec[6]
      });

      //don't grab 4 as it can't broadcast
      vector<unsigned> zcIds = {1, 7};
      vector<unsigned> zcIds_skipped = {2, 3, 5, 6};

      set<BinaryData> addrSet;
      set<BinaryData> hashSet;
      for (auto& id : zcIds)
      {
         Tx tx(rawTxVec[id - 1]);
         hashSet.insert(tx.getThisHash());
         auto localAddrSet = getAddressesForRawTx(tx);
         addrSet.insert(localAddrSet.begin(), localAddrSet.end());
      }  

      set<BinaryData> addrSet_skipped;
      set<BinaryData> hashSet_skipped;
      for (auto& id : zcIds_skipped)
      {
         Tx tx(rawTxVec[id - 1]);
         hashSet_skipped.insert(tx.getThisHash());
         auto localAddrSet = getAddressesForRawTx(tx);
         addrSet_skipped.insert(localAddrSet.begin(), localAddrSet.end());
      }


      //wait on broadcast errors
      instance->callbackPtr_->waitOnError(
         zcHashes[0], ArmoryErrorCodes::ZcBroadcast_AlreadyInMempool, broadcastId1);

      instance->callbackPtr_->waitOnError(
         zcHashes[3], ArmoryErrorCodes::ZcBroadcast_VerifyRejected, broadcastId1);

      //wait on zc
      instance->callbackPtr_->waitOnZc(hashSet_skipped, addrSet_skipped, "");

      //wait on 7
      instance->callbackPtr_->waitOnZc(hashSet, addrSet, broadcastId1);
   };

   //case 4
   auto case4 = [&](unsigned instanceId)->void
   {
      auto instance = sideInstances[instanceId];

      //push 5-6 7
      vector<unsigned> zcIds = {5, 6, 7};
      vector<unsigned> zcIds_skipped = {1, 2, 3};

      vector<BinaryData> zcs;
      set<BinaryData> addrSet;
      set<BinaryData> hashSet;
      for (auto& id : zcIds)
      {
         zcs.push_back(rawTxVec[id - 1]);
         Tx tx(rawTxVec[id - 1]);
         hashSet.insert(tx.getThisHash());
         auto localAddrSet = getAddressesForRawTx(tx);
         addrSet.insert(localAddrSet.begin(), localAddrSet.end());
      }

      set<BinaryData> addrSet_skipped;
      set<BinaryData> hashSet_skipped;
      for (auto& id : zcIds_skipped)
      {
         Tx tx(rawTxVec[id - 1]);
         hashSet_skipped.insert(tx.getThisHash());
         auto localAddrSet = getAddressesForRawTx(tx);
         addrSet_skipped.insert(localAddrSet.begin(), localAddrSet.end());
      }

      auto broadcastId1 = instance->bdvPtr_->broadcastZC(zcs);

      //wait on broadcast errors
      map<BinaryData, ArmoryErrorCodes> errorMap;
      for (auto& id : zcIds)
         errorMap.emplace(zcHashes[id - 1], ArmoryErrorCodes::ZcBroadcast_AlreadyInMempool);
      instance->callbackPtr_->waitOnErrors(errorMap, broadcastId1);

      //wait on zc
      instance->callbackPtr_->waitOnZc(hashSet_skipped, addrSet_skipped, "");
      instance->callbackPtr_->waitOnZc(hashSet, addrSet, broadcastId1);
   };

   //case 5
   auto case5 = [&](unsigned instanceId)->void
   {
      auto instance = sideInstances[instanceId];

      //push 4 5-6
      auto broadcastId1 = instance->bdvPtr_->broadcastZC({
         rawTxVec[3], 
         rawTxVec[4], rawTxVec[5]
      });

      //skip 4 as it can't broadcast
      vector<unsigned> zcIds = {5, 6};
      vector<unsigned> zcIds_skipped = {1, 2, 3};

      set<BinaryData> addrSet;
      set<BinaryData> hashSet;
      for (auto& id : zcIds)
      {
         Tx tx(rawTxVec[id - 1]);
         hashSet.insert(tx.getThisHash());
         auto localAddrSet = getAddressesForRawTx(tx);
         addrSet.insert(localAddrSet.begin(), localAddrSet.end());
      }

      set<BinaryData> addrSet_skipped;
      set<BinaryData> hashSet_skipped;
      for (auto& id : zcIds_skipped)
      {
         Tx tx(rawTxVec[id - 1]);
         hashSet_skipped.insert(tx.getThisHash());
         auto localAddrSet = getAddressesForRawTx(tx);
         addrSet_skipped.insert(localAddrSet.begin(), localAddrSet.end());
      }

      //wait on broadcast errors
      map<BinaryData, ArmoryErrorCodes> errorMap;
      for (auto& id : zcIds)
         errorMap.emplace(zcHashes[id - 1], ArmoryErrorCodes::ZcBroadcast_AlreadyInMempool);
      instance->callbackPtr_->waitOnErrors(errorMap, broadcastId1);

      instance->callbackPtr_->waitOnError(
         zcHashes[3], ArmoryErrorCodes::ZcBroadcast_VerifyRejected, broadcastId1);

      //wait on zc
      instance->callbackPtr_->waitOnZc(hashSet_skipped, addrSet_skipped, "");
      instance->callbackPtr_->waitOnZc(hashSet, addrSet, broadcastId1);
   };

   //main instance
   {
      //set zc inv delay, this will allow for batches in side jobs to 
      //collide with the original one
      nodePtr_->stallNextZc(3); //in seconds

      //push 1-2-3 & 5-6
      vector<unsigned> zcIds = {1, 2, 3, 5, 6};

      vector<BinaryData> zcs;
      set<BinaryData> scrAddrSet;
      set<BinaryData> hashes;
      for (auto& id : zcIds)
      {
         zcs.push_back(rawTxVec[id - 1]);
         Tx tx(zcs.back());
         hashes.insert(tx.getThisHash());
         auto localAddrSet = getAddressesForRawTx(tx);
         scrAddrSet.insert(localAddrSet.begin(), localAddrSet.end());
      }

      auto broadcastId1 = mainInstance->bdvPtr_->broadcastZC(zcs);
      
      /*
      delay for 1 second before starting side jobs to make sure the 
      primary broadcast is first in line
      */
      this_thread::sleep_for(chrono::seconds(1));

      //start the side jobs
      vector<thread> threads;
      for (unsigned i=0; i<3; i++)
         threads.push_back(thread(case1, i));

      for (unsigned i=3; i<6; i++)
         threads.push_back(thread(case2, i));

      //needs case3 to broadcast before case 4
      threads.push_back(thread(case3, 6));
      this_thread::sleep_for(chrono::milliseconds(500));

      for (unsigned i=7; i<10; i++)
         threads.push_back(thread(case4, i));

      for (unsigned i=10; i<13; i++)
         threads.push_back(thread(case5, i));

      //wait on zc
      mainInstance->callbackPtr_->waitOnZc(hashes, scrAddrSet, broadcastId1);

      //wait on side jobs
      for (auto& thr : threads)
      {
         if (thr.joinable())
            thr.join();
      }

      //done
   }


   //cleanup
   auto&& bdvObj2 = AsyncClient::BlockDataViewer::getNewBDV(
      "127.0.0.1", NetworkSettings::listenPort(), ArmoryConfig::getDataDir(),
      authPeersPassLbd_, NetworkSettings::ephemeralPeers(), true, nullptr);
   bdvObj2->addPublicKey(serverPubkey);
   bdvObj2->connectToRemote();

   bdvObj2->shutdown(NetworkSettings::cookie());
   WebSocketServer::waitOnShutdown();

   EXPECT_EQ(theBDMt_->bdm()->zeroConfCont()->getMatcherMapSize(), 0);

   delete theBDMt_;
   theBDMt_ = nullptr;
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_Supernode_WebSocket, BroadcastSameZC_ManyThreads_RPCFallback)
{
   struct WSClient
   {
      shared_ptr<AsyncClient::BlockDataViewer> bdvPtr_;
      AsyncClient::BtcWallet wlt_;
      shared_ptr<DBTestUtils::UTCallback> callbackPtr_;

      WSClient(
         shared_ptr<AsyncClient::BlockDataViewer> bdvPtr, 
         AsyncClient::BtcWallet& wlt,
         shared_ptr<DBTestUtils::UTCallback> callbackPtr) :
         bdvPtr_(bdvPtr), wlt_(move(wlt)), callbackPtr_(callbackPtr)
      {}
   };

   TestUtils::setBlocks({ "0", "1", "2", "3", "4", "5" }, blk0dat_);
   WebSocketServer::initAuthPeers(authPeersPassLbd_);
   WebSocketServer::start(theBDMt_, true);
   auto&& serverPubkey = WebSocketServer::getPublicKey();
   theBDMt_->start(DBSettings::initMode());

   //create BDV lambda
   auto setupBDV = [this, &serverPubkey](void)->shared_ptr<WSClient>
   {
      auto pCallback = make_shared<DBTestUtils::UTCallback>();
      auto&& bdvObj = AsyncClient::BlockDataViewer::getNewBDV(
         "127.0.0.1", NetworkSettings::listenPort(), 
         ArmoryConfig::getDataDir(),
         authPeersPassLbd_, 
         NetworkSettings::ephemeralPeers(), true, //public server
         pCallback);
      bdvObj->addPublicKey(serverPubkey);
      bdvObj->connectToRemote();
      bdvObj->registerWithDB(BitcoinSettings::getMagicBytes());

      auto&& wallet1 = bdvObj->instantiateWallet("wallet1");

      vector<BinaryData> _scrAddrVec1;
      _scrAddrVec1.push_back(TestChain::scrAddrA);
      _scrAddrVec1.push_back(TestChain::scrAddrB);
      _scrAddrVec1.push_back(TestChain::scrAddrC);
      _scrAddrVec1.push_back(TestChain::scrAddrD);
      _scrAddrVec1.push_back(TestChain::scrAddrE);
      _scrAddrVec1.push_back(TestChain::scrAddrF);

      vector<string> walletRegIDs;
      walletRegIDs.push_back(
         wallet1.registerAddresses(_scrAddrVec1, false));

      //wait on registration ack
      pCallback->waitOnManySignals(BDMAction_Refresh, walletRegIDs);

      //go online
      bdvObj->goOnline();
      pCallback->waitOnSignal(BDMAction_Ready);

      auto client = make_shared<WSClient>(bdvObj, wallet1, pCallback);
      return client;
   };

   //create main bdv instance
   auto mainInstance = setupBDV();

   /*
   create a batch of zc with chains:
      1-2-3
      1-4 (4 conflicts with 2)
      5-6
      7
   */

   vector<BinaryData> rawTxVec, zcHashes;
   map<BinaryData, map<unsigned, UTXO>> outputMap;
   {
      //instantiate resolver feed overloaded object
      auto feed = make_shared<ResolverUtils::TestResolverFeed>();
      feed->addPrivKey(TestChain::privKeyAddrB);
      feed->addPrivKey(TestChain::privKeyAddrC);
      feed->addPrivKey(TestChain::privKeyAddrD);
      feed->addPrivKey(TestChain::privKeyAddrE);
      feed->addPrivKey(TestChain::privKeyAddrF);

      //utxo from raw tx lambda
      auto getUtxoFromRawTx = [&outputMap](BinaryData& rawTx, unsigned id)->UTXO
      {
         Tx tx(rawTx);
         if (id > tx.getNumTxOut())
            throw runtime_error("invalid txout count");

         auto&& txOut = tx.getTxOutCopy(id);

         UTXO utxo;
         utxo.unserializeRaw(txOut.serialize());
         utxo.txOutIndex_ = id;
         utxo.txHash_ = tx.getThisHash();

         auto& idMap = outputMap[utxo.txHash_];
         idMap[id] = utxo;

         return utxo;
      };

      //grab utxos for scrAddrB, scrAddrC, scrAddrE
      auto promUtxo = make_shared<promise<vector<UTXO>>>();
      auto futUtxo = promUtxo->get_future();
      auto getUtxoLbd = [promUtxo](ReturnMessage<vector<UTXO>> msg)->void
      {
         promUtxo->set_value(msg.get());
      };

      mainInstance->wlt_.getSpendableTxOutListForValue(UINT64_MAX, getUtxoLbd);
      vector<UTXO> utxosB, utxosC, utxosE;
      {
         auto&& utxoVec = futUtxo.get();
         for (auto& utxo : utxoVec)
         {
            if (utxo.getRecipientScrAddr() == TestChain::scrAddrB)
               utxosB.push_back(utxo);
            else if (utxo.getRecipientScrAddr() == TestChain::scrAddrC)
               utxosC.push_back(utxo);
            else if (utxo.getRecipientScrAddr() == TestChain::scrAddrE)
               utxosE.push_back(utxo);

            auto& idMap = outputMap[utxo.txHash_];
            idMap[utxo.txOutIndex_] = utxo;
         }
      }

      ASSERT_FALSE(utxosB.empty());
      ASSERT_FALSE(utxosC.empty());
      ASSERT_FALSE(utxosE.empty());

      /*create the transactions*/

      //1
      {
         //20 from B, 5 to A, change to D
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxosB[0]);
         signer.addSpender(spender);

         auto recA = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrA.getSliceCopy(1, 20), 5 * COIN);
         signer.addRecipient(recA);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrD.getSliceCopy(1, 20), 
            spender->getValue() - recA->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTxVec.push_back(signer.serializeSignedTx());
         Tx tx(rawTxVec.back());
         zcHashes.push_back(tx.getThisHash());
      }

      //2
      {
         auto utxoD = getUtxoFromRawTx(rawTxVec[0], 1);

         //15 from D, 10 to E, change to F
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxoD);
         signer.addSpender(spender);

         auto recE = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrE.getSliceCopy(1, 20), 10 * COIN);
         signer.addRecipient(recE);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrF.getSliceCopy(1, 20), 
            spender->getValue() - recE->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTxVec.push_back(signer.serializeSignedTx());
         Tx tx(rawTxVec.back());
         zcHashes.push_back(tx.getThisHash());
      }
      
      //3
      {
         auto utxoF = getUtxoFromRawTx(rawTxVec[1], 1);

         //5 from F, 5 to B
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxoF);
         signer.addSpender(spender);

         auto recB = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrB.getSliceCopy(1, 20), 5 * COIN);
         signer.addRecipient(recB);

         signer.setFeed(feed);
         signer.sign();
         rawTxVec.push_back(signer.serializeSignedTx());
         Tx tx(rawTxVec.back());
         zcHashes.push_back(tx.getThisHash());
      }

      //4
      {
         auto utxoA = getUtxoFromRawTx(rawTxVec[0], 1);

         //15 from D, 14 to C
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxoA);
         signer.addSpender(spender);

         auto recC = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrC.getSliceCopy(1, 20), 14 * COIN);
         signer.addRecipient(recC);

         signer.setFeed(feed);
         signer.sign();
         rawTxVec.push_back(signer.serializeSignedTx());
         Tx tx(rawTxVec.back());
         zcHashes.push_back(tx.getThisHash());
      }

      //5
      {
         //10 from C, 10 to D
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxosC[0]);
         signer.addSpender(spender);

         auto recD = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrD.getSliceCopy(1, 20), 10 * COIN);
         signer.addRecipient(recD);

         signer.setFeed(feed);
         signer.sign();
         rawTxVec.push_back(signer.serializeSignedTx());
         Tx tx(rawTxVec.back());
         zcHashes.push_back(tx.getThisHash());
      }

      //6
      {
         auto utxoD = getUtxoFromRawTx(rawTxVec[4], 0);

         //10 from D, 5 to F, change to A
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxoD);
         signer.addSpender(spender);

         auto recF = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrF.getSliceCopy(1, 20), 5 * COIN);
         signer.addRecipient(recF);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrA.getSliceCopy(1, 20), 
            spender->getValue() - recF->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTxVec.push_back(signer.serializeSignedTx());
         Tx tx(rawTxVec.back());
         zcHashes.push_back(tx.getThisHash());
      }

      //7
      {
         //20 from E, 10 to F, change to A
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxosE[0]);
         signer.addSpender(spender);

         auto recF = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrF.getSliceCopy(1, 20), 10 * COIN);
         signer.addRecipient(recF);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrA.getSliceCopy(1, 20), 
            spender->getValue() - recF->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTxVec.push_back(signer.serializeSignedTx());
         Tx tx(rawTxVec.back());
         zcHashes.push_back(tx.getThisHash());
      }
   }

   //3 case1, 3 case2, 1 case3, 3 case4, 3 case5
   unsigned N = 13;

   //create N side instances
   vector<shared_ptr<WSClient>> sideInstances;
   for (unsigned i=0; i<N; i++)
      sideInstances.emplace_back(setupBDV());

   //get addresses for tx lambda
   auto getAddressesForRawTx = [&outputMap](const Tx& tx)->set<BinaryData>
   {
      set<BinaryData> addrSet;

      for (unsigned i=0; i<tx.getNumTxIn(); i++)
      {
         auto txin = tx.getTxInCopy(i);
         auto op = txin.getOutPoint();

         auto hashIter = outputMap.find(op.getTxHash());
         EXPECT_TRUE(hashIter != outputMap.end());

         auto idIter = hashIter->second.find(op.getTxOutIndex());
         EXPECT_TRUE(idIter != hashIter->second.end());

         auto& utxo = idIter->second;
         addrSet.insert(utxo.getRecipientScrAddr());
      }

      for (unsigned i=0; i<tx.getNumTxOut(); i++)
      {
         auto txout = tx.getTxOutCopy(i);
         addrSet.insert(txout.getScrAddressStr());
      }

      return addrSet;
   };

   set<BinaryData> mainScrAddrSet;
   set<BinaryData> mainHashes;   
   {
      vector<unsigned> zcIds = {1, 2, 3, 5, 6};
      for (auto& id : zcIds)
      {
         Tx tx(rawTxVec[id - 1]);
         mainHashes.insert(tx.getThisHash());
         auto localAddrSet = getAddressesForRawTx(tx);
         mainScrAddrSet.insert(localAddrSet.begin(), localAddrSet.end());
      }   
   }

   //case 1
   auto case1 = [&](unsigned instanceId)->void
   {
      auto instance = sideInstances[instanceId];

      //push 1-2-3
      vector<unsigned> zcIds = {1, 2, 3};

      //ids for the zc we are not broadcasting but which addresses we watch
      vector<unsigned> zcIds_skipped = {5, 6};

      vector<BinaryData> zcs;
      set<BinaryData> addrSet;
      set<BinaryData> hashSet;
      for (auto& id : zcIds)
      {
         zcs.push_back(rawTxVec[id - 1]);
         Tx tx(rawTxVec[id - 1]);
         hashSet.insert(tx.getThisHash());
         auto localAddrSet = getAddressesForRawTx(tx);
         addrSet.insert(localAddrSet.begin(), localAddrSet.end());
      }

      set<BinaryData> addrSet_skipped;
      set<BinaryData> hashSet_skipped;
      for (auto& id : zcIds_skipped)
      {
         Tx tx(rawTxVec[id - 1]);
         hashSet_skipped.insert(tx.getThisHash());
         auto localAddrSet = getAddressesForRawTx(tx);
         addrSet_skipped.insert(localAddrSet.begin(), localAddrSet.end());
      }

      auto broadcastId1 = instance->bdvPtr_->broadcastZC(zcs);

      //wait on zc
      instance->callbackPtr_->waitOnZc(hashSet, addrSet, broadcastId1);
      instance->callbackPtr_->waitOnZc(hashSet_skipped, addrSet_skipped, "");

      //wait on broadcast errors
      map<BinaryData, ArmoryErrorCodes> errorMap;
      for (auto& id : zcIds)
         errorMap.emplace(zcHashes[id - 1], ArmoryErrorCodes::ZcBroadcast_AlreadyInMempool);
      instance->callbackPtr_->waitOnErrors(errorMap, broadcastId1);
   };

   //case 2
   auto case2 = [&](unsigned instanceId)->void
   {
      auto instance = sideInstances[instanceId];

      //push 5-6
      vector<unsigned> zcIds = {5, 6};
      vector<unsigned> zcIds_skipped = {1, 2, 3};

      vector<BinaryData> zcs;
      set<BinaryData> addrSet;
      set<BinaryData> hashSet;
      for (auto& id : zcIds)
      {
         zcs.push_back(rawTxVec[id - 1]);
         Tx tx(rawTxVec[id - 1]);
         hashSet.insert(tx.getThisHash());
         auto localAddrSet = getAddressesForRawTx(tx);
         addrSet.insert(localAddrSet.begin(), localAddrSet.end());
      }   

      set<BinaryData> addrSet_skipped;
      set<BinaryData> hashSet_skipped;
      for (auto& id : zcIds_skipped)
      {
         Tx tx(rawTxVec[id - 1]);
         hashSet_skipped.insert(tx.getThisHash());
         auto localAddrSet = getAddressesForRawTx(tx);
         addrSet_skipped.insert(localAddrSet.begin(), localAddrSet.end());
      }

      auto broadcastId1 = instance->bdvPtr_->broadcastZC(zcs);

      //wait on zc
      instance->callbackPtr_->waitOnZc(hashSet_skipped, addrSet_skipped, "");
      instance->callbackPtr_->waitOnZc(hashSet, addrSet, broadcastId1);

      //wait on broadcast errors
      map<BinaryData, ArmoryErrorCodes> errorMap;
      for (auto& id : zcIds)
         errorMap.emplace(zcHashes[id - 1], ArmoryErrorCodes::ZcBroadcast_AlreadyInMempool);
      instance->callbackPtr_->waitOnErrors(errorMap, broadcastId1);

   };

   //case 3
   auto case3 = [&](unsigned instanceId)->void
   {
      auto instance = sideInstances[instanceId];

      //push 1-4 7
      auto broadcastId1 = instance->bdvPtr_->broadcastZC({
         rawTxVec[0], rawTxVec[3],
         rawTxVec[6]
      });

      //don't grab 4 as it can't broadcast
      vector<unsigned> zcIds = {1, 7};
      vector<unsigned> zcIds_skipped = {2, 3, 5, 6};

      set<BinaryData> addrSet;
      set<BinaryData> hashSet;
      for (auto& id : zcIds)
      {
         Tx tx(rawTxVec[id - 1]);
         hashSet.insert(tx.getThisHash());
         auto localAddrSet = getAddressesForRawTx(tx);
         addrSet.insert(localAddrSet.begin(), localAddrSet.end());
      }  

      set<BinaryData> addrSet_skipped;
      set<BinaryData> hashSet_skipped;
      for (auto& id : zcIds_skipped)
      {
         Tx tx(rawTxVec[id - 1]);
         hashSet_skipped.insert(tx.getThisHash());
         auto localAddrSet = getAddressesForRawTx(tx);
         addrSet_skipped.insert(localAddrSet.begin(), localAddrSet.end());
      }

      //wait on zc
      instance->callbackPtr_->waitOnZc_OutOfOrder(hashSet_skipped, "");

      //wait on 7
      instance->callbackPtr_->waitOnZc_OutOfOrder(hashSet, broadcastId1);

      //wait on broadcast errors
      instance->callbackPtr_->waitOnError(
         zcHashes[0], ArmoryErrorCodes::ZcBroadcast_AlreadyInMempool, broadcastId1);

      instance->callbackPtr_->waitOnError(
         zcHashes[3], ArmoryErrorCodes::ZcBroadcast_VerifyRejected, broadcastId1);
   };

   //case 4
   auto case4 = [&](unsigned instanceId)->void
   {
      auto instance = sideInstances[instanceId];

      //push 5-6 7
      vector<unsigned> zcIds = {5, 6, 7};
      vector<unsigned> zcIds_skipped = {1, 2, 3};

      vector<BinaryData> zcs;
      set<BinaryData> addrSet;
      set<BinaryData> hashSet;
      for (auto& id : zcIds)
      {
         zcs.push_back(rawTxVec[id - 1]);
         Tx tx(rawTxVec[id - 1]);
         hashSet.insert(tx.getThisHash());
         auto localAddrSet = getAddressesForRawTx(tx);
         addrSet.insert(localAddrSet.begin(), localAddrSet.end());
      }

      set<BinaryData> addrSet_skipped;
      set<BinaryData> hashSet_skipped;
      for (auto& id : zcIds_skipped)
      {
         Tx tx(rawTxVec[id - 1]);
         hashSet_skipped.insert(tx.getThisHash());
         auto localAddrSet = getAddressesForRawTx(tx);
         addrSet_skipped.insert(localAddrSet.begin(), localAddrSet.end());
      }

      auto broadcastId1 = instance->bdvPtr_->broadcastZC(zcs);

      //wait on broadcast errors
      map<BinaryData, ArmoryErrorCodes> errorMap;
      for (auto& id : zcIds)
         errorMap.emplace(zcHashes[id - 1], ArmoryErrorCodes::ZcBroadcast_AlreadyInMempool);
      instance->callbackPtr_->waitOnErrors(errorMap, broadcastId1);

      //wait on zc
      instance->callbackPtr_->waitOnZc(hashSet_skipped, addrSet_skipped, "");
      instance->callbackPtr_->waitOnZc(hashSet, addrSet, broadcastId1);
   };

   //case 5
   auto case5 = [&](unsigned instanceId)->void
   {
      auto instance = sideInstances[instanceId];

      //push 4 5-6
      auto broadcastId1 = instance->bdvPtr_->broadcastZC({
         rawTxVec[3], 
         rawTxVec[4], rawTxVec[5]
      });

      //skip 4 as it can't broadcast
      vector<unsigned> zcIds = {5, 6};
      vector<unsigned> zcIds_skipped = {1, 2, 3};

      set<BinaryData> addrSet;
      set<BinaryData> hashSet;
      for (auto& id : zcIds)
      {
         Tx tx(rawTxVec[id - 1]);
         hashSet.insert(tx.getThisHash());
         auto localAddrSet = getAddressesForRawTx(tx);
         addrSet.insert(localAddrSet.begin(), localAddrSet.end());
      }

      set<BinaryData> addrSet_skipped;
      set<BinaryData> hashSet_skipped;
      for (auto& id : zcIds_skipped)
      {
         Tx tx(rawTxVec[id - 1]);
         hashSet_skipped.insert(tx.getThisHash());
         auto localAddrSet = getAddressesForRawTx(tx);
         addrSet_skipped.insert(localAddrSet.begin(), localAddrSet.end());
      }

      //wait on broadcast errors
      map<BinaryData, ArmoryErrorCodes> errorMap;
      for (auto& id : zcIds)
         errorMap.emplace(zcHashes[id - 1], ArmoryErrorCodes::ZcBroadcast_AlreadyInMempool);
      instance->callbackPtr_->waitOnErrors(errorMap, broadcastId1);

      instance->callbackPtr_->waitOnError(
         zcHashes[3], ArmoryErrorCodes::ZcBroadcast_VerifyRejected, broadcastId1);

      //wait on zc
      instance->callbackPtr_->waitOnZc(hashSet_skipped, addrSet_skipped, "");
      instance->callbackPtr_->waitOnZc(hashSet, addrSet, broadcastId1);
   };

   //main instance
   {
      //skip all zc to force a RPC fallback
      nodePtr_->skipZc(100000);

      //push 1-2-3 & 5-6
      vector<unsigned> zcIds = {1, 2, 3, 5, 6};

      vector<BinaryData> zcs;
      set<BinaryData> scrAddrSet;
      set<BinaryData> hashes;
      for (auto& id : zcIds)
      {
         zcs.push_back(rawTxVec[id - 1]);
         Tx tx(zcs.back());
         hashes.insert(tx.getThisHash());
         auto localAddrSet = getAddressesForRawTx(tx);
         scrAddrSet.insert(localAddrSet.begin(), localAddrSet.end());
      }

      auto broadcastId1 = mainInstance->bdvPtr_->broadcastZC(zcs);
      
      /*
      delay for 1 second before starting side jobs to make sure the 
      primary broadcast is first in line
      */
      this_thread::sleep_for(chrono::seconds(1));

      //start the side jobs
      vector<thread> threads;
      for (unsigned i=0; i<3; i++)
         threads.push_back(thread(case1, i));

      for (unsigned i=3; i<6; i++)
         threads.push_back(thread(case2, i));

      //needs case3 to broadcast before case 4
      threads.push_back(thread(case3, 6));
      this_thread::sleep_for(chrono::milliseconds(500));

      for (unsigned i=7; i<10; i++)
         threads.push_back(thread(case4, i));

      for (unsigned i=10; i<13; i++)
         threads.push_back(thread(case5, i));

      //wait on zc
      mainInstance->callbackPtr_->waitOnZc(hashes, scrAddrSet, broadcastId1);

      //wait on side jobs
      for (auto& thr : threads)
      {
         if (thr.joinable())
            thr.join();
      }

      //done
   }

   //cleanup
   auto&& bdvObj2 = AsyncClient::BlockDataViewer::getNewBDV(
      "127.0.0.1", NetworkSettings::listenPort(), ArmoryConfig::getDataDir(),
      authPeersPassLbd_, NetworkSettings::ephemeralPeers(), true, nullptr);
   bdvObj2->addPublicKey(serverPubkey);
   bdvObj2->connectToRemote();

   bdvObj2->shutdown(NetworkSettings::cookie());
   WebSocketServer::waitOnShutdown();

   EXPECT_EQ(theBDMt_->bdm()->zeroConfCont()->getMatcherMapSize(), 0);

   delete theBDMt_;
   theBDMt_ = nullptr;
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_Supernode_WebSocket, BroadcastSameZC_RPCThenP2P)
{
   struct WSClient
   {
      shared_ptr<AsyncClient::BlockDataViewer> bdvPtr_;
      AsyncClient::BtcWallet wlt_;
      shared_ptr<DBTestUtils::UTCallback> callbackPtr_;

      WSClient(
         shared_ptr<AsyncClient::BlockDataViewer> bdvPtr, 
         AsyncClient::BtcWallet& wlt,
         shared_ptr<DBTestUtils::UTCallback> callbackPtr) :
         bdvPtr_(bdvPtr), wlt_(move(wlt)), callbackPtr_(callbackPtr)
      {}
   };

   TestUtils::setBlocks({ "0", "1", "2", "3", "4", "5" }, blk0dat_);
   WebSocketServer::initAuthPeers(authPeersPassLbd_);
   WebSocketServer::start(theBDMt_, true);
   auto&& serverPubkey = WebSocketServer::getPublicKey();
   theBDMt_->start(DBSettings::initMode());

   //create BDV lambda
   auto setupBDV = [this, &serverPubkey](void)->shared_ptr<WSClient>
   {
      auto pCallback = make_shared<DBTestUtils::UTCallback>();
      auto&& bdvObj = AsyncClient::BlockDataViewer::getNewBDV(
         "127.0.0.1", NetworkSettings::listenPort(), 
         ArmoryConfig::getDataDir(),
         authPeersPassLbd_, 
         NetworkSettings::ephemeralPeers(), true, //public server
         pCallback);
      bdvObj->addPublicKey(serverPubkey);
      bdvObj->connectToRemote();
      bdvObj->registerWithDB(BitcoinSettings::getMagicBytes());

      auto&& wallet1 = bdvObj->instantiateWallet("wallet1");

      vector<BinaryData> _scrAddrVec1;
      _scrAddrVec1.push_back(TestChain::scrAddrA);
      _scrAddrVec1.push_back(TestChain::scrAddrB);
      _scrAddrVec1.push_back(TestChain::scrAddrC);
      _scrAddrVec1.push_back(TestChain::scrAddrD);
      _scrAddrVec1.push_back(TestChain::scrAddrE);
      _scrAddrVec1.push_back(TestChain::scrAddrF);

      vector<string> walletRegIDs;
      walletRegIDs.push_back(
         wallet1.registerAddresses(_scrAddrVec1, false));

      //wait on registration ack
      pCallback->waitOnManySignals(BDMAction_Refresh, walletRegIDs);

      //go online
      bdvObj->goOnline();
      pCallback->waitOnSignal(BDMAction_Ready);

      auto client = make_shared<WSClient>(bdvObj, wallet1, pCallback);
      return client;
   };

   //create main bdv instance
   auto mainInstance = setupBDV();

   /*
   create a batch of zc with chains:
      1-2
      3
   */

   vector<BinaryData> rawTxVec, zcHashes;
   map<BinaryData, map<unsigned, UTXO>> outputMap;
   {
      //instantiate resolver feed overloaded object
      auto feed = make_shared<ResolverUtils::TestResolverFeed>();
      feed->addPrivKey(TestChain::privKeyAddrB);
      feed->addPrivKey(TestChain::privKeyAddrC);
      feed->addPrivKey(TestChain::privKeyAddrD);
      feed->addPrivKey(TestChain::privKeyAddrE);
      feed->addPrivKey(TestChain::privKeyAddrF);

      //utxo from raw tx lambda
      auto getUtxoFromRawTx = [&outputMap](BinaryData& rawTx, unsigned id)->UTXO
      {
         Tx tx(rawTx);
         if (id > tx.getNumTxOut())
            throw runtime_error("invalid txout count");

         auto&& txOut = tx.getTxOutCopy(id);

         UTXO utxo;
         utxo.unserializeRaw(txOut.serialize());
         utxo.txOutIndex_ = id;
         utxo.txHash_ = tx.getThisHash();

         auto& idMap = outputMap[utxo.txHash_];
         idMap[id] = utxo;

         return utxo;
      };

      //grab utxos for scrAddrB, scrAddrC, scrAddrE
      auto promUtxo = make_shared<promise<vector<UTXO>>>();
      auto futUtxo = promUtxo->get_future();
      auto getUtxoLbd = [promUtxo](ReturnMessage<vector<UTXO>> msg)->void
      {
         promUtxo->set_value(msg.get());
      };

      mainInstance->wlt_.getSpendableTxOutListForValue(UINT64_MAX, getUtxoLbd);
      vector<UTXO> utxosB, utxosC, utxosE;
      {
         auto&& utxoVec = futUtxo.get();
         for (auto& utxo : utxoVec)
         {
            if (utxo.getRecipientScrAddr() == TestChain::scrAddrB)
               utxosB.push_back(utxo);
            else if (utxo.getRecipientScrAddr() == TestChain::scrAddrC)
               utxosC.push_back(utxo);
            else if (utxo.getRecipientScrAddr() == TestChain::scrAddrE)
               utxosE.push_back(utxo);

            auto& idMap = outputMap[utxo.txHash_];
            idMap[utxo.txOutIndex_] = utxo;
         }
      }

      ASSERT_FALSE(utxosB.empty());
      ASSERT_FALSE(utxosC.empty());
      ASSERT_FALSE(utxosE.empty());

      /*create the transactions*/

      //1
      {
         //20 from B, 5 to A, change to D
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxosB[0]);
         signer.addSpender(spender);

         auto recA = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrA.getSliceCopy(1, 20), 5 * COIN);
         signer.addRecipient(recA);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrD.getSliceCopy(1, 20), 
            spender->getValue() - recA->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTxVec.push_back(signer.serializeSignedTx());
         Tx tx(rawTxVec.back());
         zcHashes.push_back(tx.getThisHash());
      }

      //2
      {
         auto utxoD = getUtxoFromRawTx(rawTxVec[0], 1);

         //15 from D, 10 to E, change to F
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxoD);
         signer.addSpender(spender);

         auto recE = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrE.getSliceCopy(1, 20), 10 * COIN);
         signer.addRecipient(recE);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrF.getSliceCopy(1, 20), 
            spender->getValue() - recE->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTxVec.push_back(signer.serializeSignedTx());
         Tx tx(rawTxVec.back());
         zcHashes.push_back(tx.getThisHash());
      }
      
      //3
      {
         //20 from E, 10 to F, change to A
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxosE[0]);
         signer.addSpender(spender);

         auto recF = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrF.getSliceCopy(1, 20), 10 * COIN);
         signer.addRecipient(recF);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrA.getSliceCopy(1, 20), 
            spender->getValue() - recF->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTxVec.push_back(signer.serializeSignedTx());
         Tx tx(rawTxVec.back());
         zcHashes.push_back(tx.getThisHash());
      }
   }

   unsigned N = 1;

   //create N side instances
   vector<shared_ptr<WSClient>> sideInstances;
   for (unsigned i=0; i<N; i++)
      sideInstances.emplace_back(setupBDV());   

   //get addresses for tx lambda
   auto getAddressesForRawTx = [&outputMap](const Tx& tx)->set<BinaryData>
   {
      set<BinaryData> addrSet;

      for (unsigned i=0; i<tx.getNumTxIn(); i++)
      {
         auto txin = tx.getTxInCopy(i);
         auto op = txin.getOutPoint();

         auto hashIter = outputMap.find(op.getTxHash());
         EXPECT_TRUE(hashIter != outputMap.end());

         auto idIter = hashIter->second.find(op.getTxOutIndex());
         EXPECT_TRUE(idIter != hashIter->second.end());

         auto& utxo = idIter->second;
         addrSet.insert(utxo.getRecipientScrAddr());
      }

      for (unsigned i=0; i<tx.getNumTxOut(); i++)
      {
         auto txout = tx.getTxOutCopy(i);
         addrSet.insert(txout.getScrAddressStr());
      }

      return addrSet;
   };

   set<BinaryData> mainScrAddrSet;
   set<BinaryData> mainHashes;   
   {
      vector<unsigned> zcIds = {1, 2};
      for (auto& id : zcIds)
      {
         Tx tx(rawTxVec[id - 1]);
         mainHashes.insert(tx.getThisHash());
         auto localAddrSet = getAddressesForRawTx(tx);
         mainScrAddrSet.insert(localAddrSet.begin(), localAddrSet.end());
      }   
   }

   //case 1
   auto case1 = [&](unsigned instanceId)->void
   {
      auto instance = sideInstances[instanceId];

      //push 1-2, 3
      vector<unsigned> zcIds = {1, 2, 3};

      vector<BinaryData> zcs;
      set<BinaryData> addrSet;
      set<BinaryData> hashSet;
      for (auto& id : zcIds)
      {
         zcs.push_back(rawTxVec[id - 1]);
         Tx tx(rawTxVec[id - 1]);
         hashSet.insert(tx.getThisHash());
         auto localAddrSet = getAddressesForRawTx(tx);
         addrSet.insert(localAddrSet.begin(), localAddrSet.end());
      }

      auto broadcastId1 = instance->bdvPtr_->broadcastZC(zcs);

      //wait on broadcast errors
      map<BinaryData, ArmoryErrorCodes> errorMap;
      errorMap.emplace(zcHashes[0], ArmoryErrorCodes::ZcBroadcast_AlreadyInMempool);
      instance->callbackPtr_->waitOnErrors(errorMap, broadcastId1);

      //wait on zc
      instance->callbackPtr_->waitOnZc(hashSet, addrSet, broadcastId1);
   };

   //main instance
   {
      //set RPC, this will allow for batches in side jobs to 
      //collide with the original one
      rpcNode_->stallNextZc(3); //in seconds

      //push 1-2

      set<BinaryData> scrAddrSet1, scrAddrSet2;
      BinaryData hash1, hash2;
         
      {
         Tx tx(rawTxVec[0]);
         hash1 = tx.getThisHash();
         scrAddrSet1 = getAddressesForRawTx(tx);
      }

      {
         Tx tx(rawTxVec[1]);
         hash2 = tx.getThisHash();
         scrAddrSet2 = getAddressesForRawTx(tx);
      }

      auto broadcastId1 = mainInstance->bdvPtr_->broadcastThroughRPC(rawTxVec[0]);
      auto broadcastId2 = mainInstance->bdvPtr_->broadcastThroughRPC(rawTxVec[1]);

      /*
      delay for 1 second before starting side jobs to make sure the 
      primary broadcast is first in line
      */
      this_thread::sleep_for(chrono::seconds(1));

      //start the side jobs
      vector<thread> threads;
      threads.push_back(thread(case1, 0));

      //wait on zc
      mainInstance->callbackPtr_->waitOnZc({hash1}, scrAddrSet1, broadcastId1);
      mainInstance->callbackPtr_->waitOnZc({hash2}, scrAddrSet2, broadcastId2);

      //wait on side jobs
      for (auto& thr : threads)
      {
         if (thr.joinable())
            thr.join();
      }

      //done
   }

   //cleanup
   auto&& bdvObj2 = AsyncClient::BlockDataViewer::getNewBDV(
      "127.0.0.1", NetworkSettings::listenPort(), ArmoryConfig::getDataDir(),
      authPeersPassLbd_, NetworkSettings::ephemeralPeers(), true, nullptr);
   bdvObj2->addPublicKey(serverPubkey);
   bdvObj2->connectToRemote();

   bdvObj2->shutdown(NetworkSettings::cookie());
   WebSocketServer::waitOnShutdown();

   EXPECT_EQ(theBDMt_->bdm()->zeroConfCont()->getMatcherMapSize(), 0);

   delete theBDMt_;
   theBDMt_ = nullptr;
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(ZeroConfTests_Supernode_WebSocket, RebroadcastInvalidBatch)
{
   TestUtils::setBlocks({ "0", "1", "2", "3", "4", "5" }, blk0dat_);
   WebSocketServer::initAuthPeers(authPeersPassLbd_);
   WebSocketServer::start(theBDMt_, true);
   auto&& serverPubkey = WebSocketServer::getPublicKey();
   theBDMt_->start(DBSettings::initMode());

   {
      auto pCallback = make_shared<DBTestUtils::UTCallback>();
      auto&& bdvObj = AsyncClient::BlockDataViewer::getNewBDV(
         "127.0.0.1", NetworkSettings::listenPort(), 
         ArmoryConfig::getDataDir(),
         authPeersPassLbd_, 
         NetworkSettings::ephemeralPeers(), true, //public server
         pCallback);
      bdvObj->addPublicKey(serverPubkey);
      bdvObj->connectToRemote();
      bdvObj->registerWithDB(BitcoinSettings::getMagicBytes());

      auto&& wallet1 = bdvObj->instantiateWallet("wallet1");

      vector<BinaryData> _scrAddrVec1;
      _scrAddrVec1.push_back(TestChain::scrAddrA);
      _scrAddrVec1.push_back(TestChain::scrAddrB);
      _scrAddrVec1.push_back(TestChain::scrAddrC);
      _scrAddrVec1.push_back(TestChain::scrAddrD);
      _scrAddrVec1.push_back(TestChain::scrAddrE);
      _scrAddrVec1.push_back(TestChain::scrAddrF);

      vector<string> walletRegIDs;
      walletRegIDs.push_back(
         wallet1.registerAddresses(_scrAddrVec1, false));

      //wait on registration ack
      pCallback->waitOnManySignals(BDMAction_Refresh, walletRegIDs);

      //go online
      bdvObj->goOnline();
      pCallback->waitOnSignal(BDMAction_Ready);

      //balance fetching routine
      vector<string> walletIDs = { wallet1.walletID() };
      auto getBalances = [bdvObj, walletIDs](void)->CombinedBalances
      {
         auto promPtr = make_shared<promise<map<string, CombinedBalances>>>();
         auto fut = promPtr->get_future();
         auto balLbd = [promPtr](
            ReturnMessage<map<string, CombinedBalances>> combBal)->void
         {
            promPtr->set_value(combBal.get());
         };

         bdvObj->getCombinedBalances(walletIDs, balLbd);
         auto&& balMap = fut.get();

         if (balMap.size() != 1)
            throw runtime_error("unexpected balance map size");

         return balMap.begin()->second;
      };

      //check balances before pushing zc
      auto&& combineBalances = getBalances();
      EXPECT_EQ(combineBalances.addressBalances_.size(), 6);

      {
         auto iterA = combineBalances.addressBalances_.find(TestChain::scrAddrA);
         ASSERT_NE(iterA, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterA->second.size(), 3);
         EXPECT_EQ(iterA->second[0], 50 * COIN);

         auto iterB = combineBalances.addressBalances_.find(TestChain::scrAddrB);
         ASSERT_NE(iterB, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterB->second.size(), 3);
         EXPECT_EQ(iterB->second[0], 70 * COIN);

         auto iterC = combineBalances.addressBalances_.find(TestChain::scrAddrC);
         ASSERT_NE(iterC, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterC->second.size(), 3);
         EXPECT_EQ(iterC->second[0], 20 * COIN);

         auto iterD = combineBalances.addressBalances_.find(TestChain::scrAddrD);
         ASSERT_NE(iterD, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterD->second.size(), 3);
         EXPECT_EQ(iterD->second[0], 65 * COIN);

         auto iterE = combineBalances.addressBalances_.find(TestChain::scrAddrE);
         ASSERT_NE(iterE, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterE->second.size(), 3);
         EXPECT_EQ(iterE->second[0], 30 * COIN);

         auto iterF = combineBalances.addressBalances_.find(TestChain::scrAddrF);
         ASSERT_NE(iterF, combineBalances.addressBalances_.end());
         ASSERT_EQ(iterF->second.size(), 3);
         EXPECT_EQ(iterF->second[0], 5 * COIN);
      }
   
      //instantiate resolver feed overloaded object
      auto feed = make_shared<ResolverUtils::TestResolverFeed>();
      feed->addPrivKey(TestChain::privKeyAddrB);
      feed->addPrivKey(TestChain::privKeyAddrC);
      feed->addPrivKey(TestChain::privKeyAddrD);
      feed->addPrivKey(TestChain::privKeyAddrE);
      feed->addPrivKey(TestChain::privKeyAddrF);

      //grab utxos for scrAddrB
      auto promUtxo = make_shared<promise<vector<UTXO>>>();
      auto futUtxo = promUtxo->get_future();
      auto getUtxoLbd = [promUtxo](ReturnMessage<vector<UTXO>> msg)->void
      {
         promUtxo->set_value(msg.get());
      };

      wallet1.getSpendableTxOutListForValue(UINT64_MAX, getUtxoLbd);
      vector<UTXO> utxosB;
      {
         auto&& utxoVec = futUtxo.get();
         for (auto& utxo : utxoVec)
         {
            if (utxo.getRecipientScrAddr() != TestChain::scrAddrB)
               continue;

            utxosB.push_back(utxo);
         }
      }

      ASSERT_FALSE(utxosB.empty());

      /*create the transactions*/

      //grab utxo from raw tx
      auto getUtxoFromRawTx = [](BinaryData& rawTx, unsigned id)->UTXO
      {
         Tx tx(rawTx);
         if (id > tx.getNumTxOut())
            throw runtime_error("invalid txout count");

         auto&& txOut = tx.getTxOutCopy(id);

         UTXO utxo;
         utxo.unserializeRaw(txOut.serialize());
         utxo.txOutIndex_ = id;
         utxo.txHash_ = tx.getThisHash();

         return utxo;
      };

      BinaryData rawTx1, rawTx2;

      {
         //20 from B, 5 to A, change to D
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxosB[0]);
         signer.addSpender(spender);

         auto recA = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrA.getSliceCopy(1, 20), 5 * COIN);
         signer.addRecipient(recA);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrD.getSliceCopy(1, 20), 
            spender->getValue() - recA->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx1 = signer.serializeSignedTx();
      }

      {
         auto utxoD = getUtxoFromRawTx(rawTx1, 1);

         //15 from D, 10 to E, change to F
         Signer signer;

         auto spender = make_shared<ScriptSpender>(utxoD);
         signer.addSpender(spender);

         auto recE = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrE.getSliceCopy(1, 20), 10 * COIN);
         signer.addRecipient(recE);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrF.getSliceCopy(1, 20), 
            spender->getValue() - recE->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx2 = signer.serializeSignedTx();
      }

      BinaryData rawTx3;
      {
         //10 from E, 5 from F, 3 to A, 2 to E, 5 to D, change to C
         auto zcUtxo1 = getUtxoFromRawTx(rawTx2, 0);
         auto zcUtxo2 = getUtxoFromRawTx(rawTx2, 1);

         Signer signer;
         
         auto spender1 = make_shared<ScriptSpender>(zcUtxo1);
         auto spender2 = make_shared<ScriptSpender>(zcUtxo2);
         signer.addSpender(spender1);
         signer.addSpender(spender2);

         auto recA = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrA.getSliceCopy(1, 20), 3 * COIN);
         signer.addRecipient(recA);

         auto recE = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrE.getSliceCopy(1, 20), 2 * COIN);
         signer.addRecipient(recE);
         
         auto recD = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrD.getSliceCopy(1, 20), 5 * COIN);
         signer.addRecipient(recD);

         auto recChange = make_shared<Recipient_P2PKH>(
            TestChain::scrAddrC.getSliceCopy(1, 20),
            spender1->getValue() + spender2->getValue() - 
            recA->getValue() - recE->getValue() - recD->getValue());
         signer.addRecipient(recChange);

         signer.setFeed(feed);
         signer.sign();
         rawTx3 = signer.serializeSignedTx();
      }

      //batch push tx
      auto broadcastId1 = bdvObj->broadcastZC({ rawTx2, rawTx3 });
      map<BinaryData, ArmoryErrorCodes> errMap;
         
      Tx tx1(rawTx2);
      Tx tx2(rawTx3);
      errMap.emplace(tx1.getThisHash(), ArmoryErrorCodes::ZcBroadcast_Error);
      errMap.emplace(tx2.getThisHash(), ArmoryErrorCodes::ZcBroadcast_Error);
      pCallback->waitOnErrors(errMap, broadcastId1);

      //try again
      auto broadcastId2 = bdvObj->broadcastZC({ rawTx2, rawTx3 });
      pCallback->waitOnErrors(errMap, broadcastId2);
   }

   //cleanup
   auto&& bdvObj2 = AsyncClient::BlockDataViewer::getNewBDV(
      "127.0.0.1", NetworkSettings::listenPort(), ArmoryConfig::getDataDir(),
      authPeersPassLbd_, NetworkSettings::ephemeralPeers(), true, nullptr);
   bdvObj2->addPublicKey(serverPubkey);
   bdvObj2->connectToRemote();

   bdvObj2->shutdown(NetworkSettings::cookie());
   WebSocketServer::waitOnShutdown();

   EXPECT_EQ(theBDMt_->bdm()->zeroConfCont()->getMatcherMapSize(), 0);

   delete theBDMt_;
   theBDMt_ = nullptr;
}

////////////////////////////////////////////////////////////////////////////////
// Now actually execute all the tests
////////////////////////////////////////////////////////////////////////////////
GTEST_API_ int main(int argc, char **argv)
{
#ifdef _MSC_VER
   _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);

   WSADATA wsaData;
   WORD wVersion = MAKEWORD(2, 0);
   WSAStartup(wVersion, &wsaData);
#endif

   btc_ecc_start();

   GOOGLE_PROTOBUF_VERIFY_VERSION;
   srand(time(0));
   std::cout << "Running main() from gtest_main.cc\n";

   testing::InitGoogleTest(&argc, argv);
   int exitCode = RUN_ALL_TESTS();

   FLUSHLOG();
   CLEANUPLOG();
   google::protobuf::ShutdownProtobufLibrary();

   btc_ecc_stop();
   return exitCode;
}