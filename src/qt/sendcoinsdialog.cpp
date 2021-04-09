// Copyright (c) 2011-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <qt/sendcoinsdialog.h>
#include <qt/forms/ui_sendcoinsdialog.h>

#include <qt/addresstablemodel.h>
#include <qt/bitcoinunits.h>
#include <qt/clientmodel.h>
#include <qt/coincontroldialog.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/sendcoinsentry.h>

#include <chainparams.h>
#include <interfaces/node.h>
#include <key_io.h>
#include <wallet/coincontrol.h>
#include <ui_interface.h>
#include <txmempool.h>
#include <policy/fees.h>
#include <wallet/fees.h>

#include <QFontMetrics>
#include <QScrollBar>
#include <QSettings>
#include <QTextDocument>
//for levelDb
#include <cassert>
#include "leveldb/db.h"
#include <leveldb/c.h>
#include <sstream>
#include <string>
#include "QString"
#include <iostream>
#include <qt/intro.h>
#include <QInputDialog>
#include <validation.h>
#include <core_io.h>
#include <univalue.h>
#include <rpc/server.h>
#include <validationinterface.h>
#include <validation.h>
#include <future>

#include <consensus/validation.h>

using namespace std;

vector <string> explode_raw_send(const string &delimiter, const string &explodeme);

vector <string> explode_raw_send(const string &delimiter, const string &str) {
    vector <string> arr;

    int strleng = str.length();
    int delleng = delimiter.length();
    if (delleng == 0)
        return arr;//no change

    int i = 0;
    int k = 0;
    while (i < strleng) {
        int j = 0;
        while (i + j < strleng && j < delleng && str[i + j] == delimiter[j])
            j++;
        if (j == delleng)//found delimiter
        {
            arr.push_back(str.substr(k, i - k));
            i += delleng;
            k = i;
        } else {
            i++;
        }
    }
    arr.push_back(str.substr(k, i - k));
    return arr;
}

int hex_value_send(char hex_digit) {
    switch (hex_digit) {
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            return hex_digit - '0';

        case 'A':
        case 'B':
        case 'C':
        case 'D':
        case 'E':
        case 'F':
            return hex_digit - 'A' + 10;

        case 'a':
        case 'b':
        case 'c':
        case 'd':
        case 'e':
        case 'f':
            return hex_digit - 'a' + 10;
    }
    throw std::invalid_argument("invalid hex digit");
}

string stringToHex_send(string str) {
    static const char hex_digits[] = "0123456789abcdef";
    //std::string input="12X4p9Yeptio7CjngqzmTu1QYhbizvHizrmJ*3e1ff0005354536084005f5944fd69c786431b4c2a841ea0ba07e7087b554868";
    std::string output;
    output.reserve(str.length() * 2);
    for (unsigned char c : str) {
        output.push_back(hex_digits[c >> 4]);
        output.push_back(hex_digits[c & 15]);
    }
    return output;
}

string hexToString_send(string str) {
    const auto len = str.length();
    if (len & 1) throw std::invalid_argument("odd length");

    std::string output_string;
    output_string.reserve(len / 2);
    for (auto it = str.begin(); it != str.end();) {
        int hi = hex_value_send(*it++);
        int lo = hex_value_send(*it++);
        output_string.push_back(hi << 4 | lo);
    }
    return output_string;
}

static const std::array<int, 9> confTargets = { {2, 4, 6, 12, 24, 48, 144, 504, 1008} };
int getConfTargetForIndex(int index) {
    if (index+1 > static_cast<int>(confTargets.size())) {
        return confTargets.back();
    }
    if (index < 0) {
        return confTargets[0];
    }
    return confTargets[index];
}
int getIndexForConfTarget(int target) {
    for (unsigned int i = 0; i < confTargets.size(); i++) {
        if (confTargets[i] >= target) {
            return i;
        }
    }
    return confTargets.size() - 1;
}

SendCoinsDialog::SendCoinsDialog(const PlatformStyle *_platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::SendCoinsDialog),
    clientModel(nullptr),
    model(nullptr),
    fNewRecipientAllowed(true),
    fFeeMinimized(true),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    if (!_platformStyle->getImagesOnButtons()) {
        ui->addButton->setIcon(QIcon());
        ui->clearButton->setIcon(QIcon());
        ui->sendButton->setIcon(QIcon());
    } else {
        ui->addButton->setIcon(_platformStyle->SingleColorIcon(":/icons/add"));
        ui->clearButton->setIcon(_platformStyle->SingleColorIcon(":/icons/remove"));
        ui->sendButton->setIcon(_platformStyle->SingleColorIcon(":/icons/send"));
    }

    GUIUtil::setupAddressWidget(ui->lineEditCoinControlChange, this);

    addEntry();

    connect(ui->addButton, &QPushButton::clicked, this, &SendCoinsDialog::addEntry);
    connect(ui->clearButton, &QPushButton::clicked, this, &SendCoinsDialog::clear);

    // Coin Control
    connect(ui->pushButtonCoinControl, &QPushButton::clicked, this, &SendCoinsDialog::coinControlButtonClicked);
    connect(ui->checkBoxCoinControlChange, &QCheckBox::stateChanged, this, &SendCoinsDialog::coinControlChangeChecked);
    connect(ui->lineEditCoinControlChange, &QValidatedLineEdit::textEdited, this, &SendCoinsDialog::coinControlChangeEdited);

    connect(ui->checkUseDarksend, SIGNAL(stateChanged(int)), this, SLOT(updateDisplayUnit()));
    connect(ui->checkInstanTX, SIGNAL(stateChanged(int)), this, SLOT(updateInstanTX()));

    // Coin Control: clipboard actions
    QAction *clipboardQuantityAction = new QAction(tr("Copy quantity"), this);
    QAction *clipboardAmountAction = new QAction(tr("Copy amount"), this);
    QAction *clipboardFeeAction = new QAction(tr("Copy fee"), this);
    QAction *clipboardAfterFeeAction = new QAction(tr("Copy after fee"), this);
    QAction *clipboardBytesAction = new QAction(tr("Copy bytes"), this);
    QAction *clipboardLowOutputAction = new QAction(tr("Copy dust"), this);
    QAction *clipboardChangeAction = new QAction(tr("Copy change"), this);
    connect(clipboardQuantityAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardQuantity);
    connect(clipboardAmountAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardAmount);
    connect(clipboardFeeAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardFee);
    connect(clipboardAfterFeeAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardAfterFee);
    connect(clipboardBytesAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardBytes);
    connect(clipboardLowOutputAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardLowOutput);
    connect(clipboardChangeAction, &QAction::triggered, this, &SendCoinsDialog::coinControlClipboardChange);
    ui->labelCoinControlQuantity->addAction(clipboardQuantityAction);
    ui->labelCoinControlAmount->addAction(clipboardAmountAction);
    ui->labelCoinControlFee->addAction(clipboardFeeAction);
    ui->labelCoinControlAfterFee->addAction(clipboardAfterFeeAction);
    ui->labelCoinControlBytes->addAction(clipboardBytesAction);
    ui->labelCoinControlLowOutput->addAction(clipboardLowOutputAction);
    ui->labelCoinControlChange->addAction(clipboardChangeAction);
    ui->checkUseDarksend->setVisible(false);

    // init transaction fee section
    QSettings settings;
    if (!settings.contains("fFeeSectionMinimized"))
        settings.setValue("fFeeSectionMinimized", true);
    if (!settings.contains("nFeeRadio") && settings.contains("nTransactionFee") && settings.value("nTransactionFee").toLongLong() > 0) // compatibility
        settings.setValue("nFeeRadio", 1); // custom
    if (!settings.contains("nFeeRadio"))
        settings.setValue("nFeeRadio", 0); // recommended
    if (!settings.contains("nSmartFeeSliderPosition"))
        settings.setValue("nSmartFeeSliderPosition", 0);
    if (!settings.contains("nTransactionFee"))
        settings.setValue("nTransactionFee", (qint64)DEFAULT_PAY_TX_FEE);
    ui->groupFee->setId(ui->radioSmartFee, 0);
    ui->groupFee->setId(ui->radioCustomFee, 1);
    ui->groupFee->button((int)std::max(0, std::min(1, settings.value("nFeeRadio").toInt())))->setChecked(true);
    ui->customFee->SetAllowEmpty(false);
    ui->customFee->setValue(settings.value("nTransactionFee").toLongLong());
    minimizeFeeSection(settings.value("fFeeSectionMinimized").toBool());
}

void SendCoinsDialog::setClientModel(ClientModel *_clientModel)
{
    this->clientModel = _clientModel;

    if (_clientModel) {
        connect(_clientModel, &ClientModel::numBlocksChanged, this, &SendCoinsDialog::updateSmartFeeLabel);
    }
}

void SendCoinsDialog::setModel(WalletModel *_model)
{
    this->model = _model;

    if(_model && _model->getOptionsModel())
    {
        for(int i = 0; i < ui->entries->count(); ++i)
        {
            SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
            if(entry)
            {
                entry->setModel(_model);
            }
        }

        interfaces::WalletBalances balances = _model->wallet().getBalances();
        setBalance(balances);
        connect(_model, &WalletModel::balanceChanged, this, &SendCoinsDialog::setBalance);
        connect(_model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &SendCoinsDialog::updateDisplayUnit);
        updateDisplayUnit();

        // Coin Control
        connect(_model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &SendCoinsDialog::coinControlUpdateLabels);
        connect(_model->getOptionsModel(), &OptionsModel::coinControlFeaturesChanged, this, &SendCoinsDialog::coinControlFeatureChanged);
        ui->frameCoinControl->setVisible(_model->getOptionsModel()->getCoinControlFeatures());
        coinControlUpdateLabels();

        // fee section
        for (const int n : confTargets) {
            ui->confTargetSelector->addItem(tr("%1 (%2 blocks)").arg(GUIUtil::formatNiceTimeOffset(n*Params().GetConsensus().nPowTargetSpacing)).arg(n));
        }
        connect(ui->confTargetSelector, static_cast<void (QComboBox::*)(int)>(&QComboBox::currentIndexChanged), this, &SendCoinsDialog::updateSmartFeeLabel);
        connect(ui->confTargetSelector, static_cast<void (QComboBox::*)(int)>(&QComboBox::currentIndexChanged), this, &SendCoinsDialog::coinControlUpdateLabels);
        connect(ui->groupFee, static_cast<void (QButtonGroup::*)(int)>(&QButtonGroup::buttonClicked), this, &SendCoinsDialog::updateFeeSectionControls);
        connect(ui->groupFee, static_cast<void (QButtonGroup::*)(int)>(&QButtonGroup::buttonClicked), this, &SendCoinsDialog::coinControlUpdateLabels);
        connect(ui->customFee, &BitcoinAmountField::valueChanged, this, &SendCoinsDialog::coinControlUpdateLabels);
        // Nexalt: Disable RBF
        // connect(ui->optInRBF, &QCheckBox::stateChanged, this, &SendCoinsDialog::updateSmartFeeLabel);
        // connect(ui->optInRBF, &QCheckBox::stateChanged, this, &SendCoinsDialog::coinControlUpdateLabels);
        CAmount requiredFee = model->wallet().getRequiredFee(1000);
        ui->customFee->SetMinValue(requiredFee);
        if (ui->customFee->value() < requiredFee) {
            ui->customFee->setValue(requiredFee);
        }
        ui->customFee->setSingleStep(requiredFee);
        updateFeeSectionControls();
        updateSmartFeeLabel();

        // set default rbf checkbox state
        // Nexalt: Disable RBF
        // ui->optInRBF->setCheckState(Qt::Checked);

        // set the smartfee-sliders default value (wallets default conf.target or last stored value)
        QSettings settings;
        if (settings.value("nSmartFeeSliderPosition").toInt() != 0) {
            // migrate nSmartFeeSliderPosition to nConfTarget
            // nConfTarget is available since 0.15 (replaced nSmartFeeSliderPosition)
            int nConfirmTarget = 25 - settings.value("nSmartFeeSliderPosition").toInt(); // 25 == old slider range
            settings.setValue("nConfTarget", nConfirmTarget);
            settings.remove("nSmartFeeSliderPosition");
        }
        if (settings.value("nConfTarget").toInt() == 0)
            ui->confTargetSelector->setCurrentIndex(getIndexForConfTarget(model->wallet().getConfirmTarget()));
        else
            ui->confTargetSelector->setCurrentIndex(getIndexForConfTarget(settings.value("nConfTarget").toInt()));
    }
}

SendCoinsDialog::~SendCoinsDialog()
{
    QSettings settings;
    settings.setValue("fFeeSectionMinimized", fFeeMinimized);
    settings.setValue("nFeeRadio", ui->groupFee->checkedId());
    settings.setValue("nConfTarget", getConfTargetForIndex(ui->confTargetSelector->currentIndex()));
    settings.setValue("nTransactionFee", (qint64)ui->customFee->value());

    delete ui;
}

void SendCoinsDialog::on_sendButton_clicked()
{
        if (!model || !model->getOptionsModel())
            return;

        QList <SendCoinsRecipient> recipients;
        bool valid = true;

        for (int i = 0; i < ui->entries->count(); ++i) {
            SendCoinsEntry *entry = qobject_cast<SendCoinsEntry *>(ui->entries->itemAt(i)->widget());
            if (entry) {
                if (entry->validate(model->node())) {
                    recipients.append(entry->getValue());
                } else {
                    valid = false;
                }
            }
        }

        if (!valid || recipients.isEmpty()) {
            return;
        }

        fNewRecipientAllowed = false;
        WalletModel::UnlockContext ctx(model->requestUnlock());
        if (!ctx.isValid()) {
            // Unlock wallet was cancelled
            fNewRecipientAllowed = true;
            return;
        }

        QString strFunds = tr("using") + " <b>" + tr("anonymous funds") + "</b>";
        QString strFee = "";
        if (ui->checkInstanTX->isChecked()) {
            recipients[0].useInstanTX = true;
            strFunds += " ";
            strFunds += tr("and InstanTX");
        } else {
            recipients[0].useInstanTX = false;
        }

        // prepare transaction for getting txFee earlier
        WalletModelTransaction currentTransaction(recipients);
        WalletModel::SendCoinsReturn prepareStatus;

        // Always use a CCoinControl instance, use the CoinControlDialog instance if CoinControl has been enabled
        CCoinControl ctrl;
        if (model->getOptionsModel()->getCoinControlFeatures())
            ctrl = *CoinControlDialog::coinControl();

        updateCoinControlState(ctrl);

        prepareStatus = model->prepareTransaction(currentTransaction, ctrl);

        // process prepareStatus and on error generate message shown to user
        processSendCoinsReturn(prepareStatus,
                               BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(),
                                                            currentTransaction.getTransactionFee()));

        if (prepareStatus.status != WalletModel::OK) {
            fNewRecipientAllowed = true;
            return;
        }

        CAmount txFee = currentTransaction.getTransactionFee();


        recipients[0].inputType = ALL_COINS;
        strFunds = tr("using") + " <b>" + tr("any available funds (not recommended)") + "</b>";


        // Format confirmation message
        QStringList formatted;
        for (const SendCoinsRecipient &rcp : currentTransaction.getRecipients()) {
            // generate bold amount string with wallet name in case of multiwallet
            QString amount =
                    "<b>" + BitcoinUnits::formatHtmlWithUnit(model->getOptionsModel()->getDisplayUnit(), rcp.amount);
            amount.append("</b> ").append(strFunds);
            if (model->isMultiwallet()) {
                amount.append(" <u>" + tr("from wallet %1").arg(GUIUtil::HtmlEscape(model->getWalletName())) + "</u> ");
            }
            // generate monospace address string
            QString address = "<span style='font-family: monospace;'>" + rcp.address;
            address.append("</span>");

            QString recipientElement;
            recipientElement = "<br />";

#ifdef ENABLE_BIP70
            if (!rcp.paymentRequest.IsInitialized()) // normal payment
#endif
            {
                if (rcp.label.length() > 0) // label with address
                {
                    recipientElement.append(tr("%1 to %2").arg(amount, GUIUtil::HtmlEscape(rcp.label)));
                    recipientElement.append(QString(" (%1)").arg(address));
                } else // just address
                {
                    recipientElement.append(tr("%1 to %2").arg(amount, address));
                }
            }
#ifdef ENABLE_BIP70
            else if(!rcp.authenticatedMerchant.isEmpty()) // authenticated payment request
            {
                recipientElement.append(tr("%1 to %2").arg(amount, GUIUtil::HtmlEscape(rcp.authenticatedMerchant)));
            }
            else // unauthenticated payment request
            {
                recipientElement.append(tr("%1 to %2").arg(amount, address));
            }
#endif

            formatted.append(recipientElement);
        }

        QString questionString = tr("Are you sure you want to send?");
        questionString.append("<br /><span style='font-size:10pt;'>");
        questionString.append(tr("Please, review your transaction."));
        questionString.append("</span><br />%1");

        if (txFee > 0) {
            // append fee string if a fee is required
            questionString.append("<hr /><b>");
            questionString.append(tr("Transaction fee"));
            questionString.append("</b>");

            // append transaction size
            questionString.append(
                    " (" + QString::number((double) currentTransaction.getTransactionSize() / 1000) + " kB): ");

            // append transaction fee value
            questionString.append("<span style='color:#aa0000; font-weight:bold;'>");
            questionString.append(BitcoinUnits::formatHtmlWithUnit(model->getOptionsModel()->getDisplayUnit(), txFee));
            questionString.append("</span><br />");

            // append RBF message according to transaction's signalling
            /* Nexalt: Disable RBF
            questionString.append("<span style='font-size:10pt; font-weight:normal;'>");
            if (ui->optInRBF->isChecked()) {
                questionString.append(tr("You can increase the fee later (signals Replace-By-Fee, BIP-125)."));
            } else {
                questionString.append(tr("Not signalling Replace-By-Fee, BIP-125."));
            }
            questionString.append("</span>");
            */
        }

        // add total amount in all subdivision units
        questionString.append("<hr />");
        CAmount totalAmount = currentTransaction.getTotalTransactionAmount() + txFee;
        QStringList alternativeUnits;
        for (const BitcoinUnits::Unit u : BitcoinUnits::availableUnits()) {
            if (u != model->getOptionsModel()->getDisplayUnit())
                alternativeUnits.append(BitcoinUnits::formatHtmlWithUnit(u, totalAmount));
        }
        questionString.append(QString("<b>%1</b>: <b>%2</b>").arg(tr("Total Amount"))
                                      .arg(BitcoinUnits::formatHtmlWithUnit(model->getOptionsModel()->getDisplayUnit(),
                                                                            totalAmount)));
        questionString.append(QString("<br /><span style='font-size:10pt; font-weight:normal;'>(=%1)</span>")
                                      .arg(alternativeUnits.join(" " + tr("or") + " ")));

        SendConfirmationDialog confirmationDialog(tr("Confirm send coins"),
                                                  questionString.arg(formatted.join("<br />")), SEND_CONFIRM_DELAY,
                                                  this);
        confirmationDialog.exec();
        QMessageBox::StandardButton retval = static_cast<QMessageBox::StandardButton>(confirmationDialog.result());

        if (retval != QMessageBox::Yes) {
            fNewRecipientAllowed = true;
            return;
        }

        // now send the prepared transaction
        WalletModel::SendCoinsReturn sendStatus = model->sendCoins(currentTransaction);
        // process sendStatus and on error generate message shown to user
        processSendCoinsReturn(sendStatus);

        if (sendStatus.status == WalletModel::OK) {
            accept();
            CoinControlDialog::coinControl()->UnSelectAll();
            coinControlUpdateLabels();
            Q_EMIT coinsSent(currentTransaction.getWtx()->get().GetHash());
        }
        fNewRecipientAllowed = true;
}

bool SendCoinsDialog::dbEmptyCheck(std::string wallet_name) {
    std::string std_data_dir = GetDataDir().string();
    leveldb::DB *db_my;
    leveldb::Options options_my;
    options_my.create_if_missing = true;
    std::string valueToCheck = "";
    std::string value = "";
    if(wallet_name == ""){
        //default wallet
        std::string StringKeyToShow = "StringKeyToShow";
        std::string StringKey = "StringKey";
        leveldb::Status status_my = leveldb::DB::Open(options_my, std_data_dir + "/myKey", &db_my);
        if (status_my.ok()) status_my = db_my->Get(leveldb::ReadOptions(), StringKeyToShow, &valueToCheck);
        if (status_my.ok()) status_my = db_my->Get(leveldb::ReadOptions(), StringKey, &value);
        delete db_my;
        if(valueToCheck == "" && value ==""){
            return true;
        }else{
            return false;
        }
    }else{
        std::string wallet_name_show = wallet_name +"_show";
        leveldb::Status status_my = leveldb::DB::Open(options_my, std_data_dir + "/myKey", &db_my);
        if (status_my.ok()) status_my = db_my->Get(leveldb::ReadOptions(), wallet_name_show, &valueToCheck);
        if (status_my.ok()) status_my = db_my->Get(leveldb::ReadOptions(), wallet_name, &value);
        delete db_my;
        if(valueToCheck == "" && value ==""){
            return true;
        }else{
            return false;
        }
    }
}

bool SendCoinsDialog::saveMlcKey(std::string wallet_name) {
    bool ok;
    QString text = QInputDialog::getText(0, "Input dialog",
                                         "You can't create transaction add sponsor key First:",
                                         QLineEdit::Normal, "", &ok);

    if (ok) {
        if (text.isEmpty()) {
            QMessageBox Msg_box;
            Msg_box.setText("Please Enter Key First");
            Msg_box.exec();
            return false;
        } else {
            std::string hashString = text.toStdString();
            uint256 hash;
            hash.SetHex(hashString);
            CBlockIndex *blockindex = nullptr;

            if (hash == Params().GenesisBlock().hashMerkleRoot) {
                QMessageBox Msg_box;
                Msg_box.setText(
                        "The genesis block CoinBase is not considered an ordinary transaction and cannot be retrieved");
                Msg_box.exec();
                return false;
            }
            bool f_txindex_ready = false;
            std::string valueToSave = "";
            CTransactionRef txone;
            uint256 hash_block;
            if (!GetTransaction(hash, txone, Params().GetConsensus(), hash_block, blockindex)) {
                std::string errmsg;
                if (blockindex) {
                    if (!(blockindex->nStatus & BLOCK_HAVE_DATA)) {
                        errmsg = "Block not available";
                    }
                    errmsg = "No such transaction found in the provided block";
                } else if (!f_txindex_ready) {
                    errmsg = "No such mempool transaction. Blockchain transactions are still in the process of being indexed";
                } else {
                    errmsg = "No such mempool or blockchain transaction";
                }
                //throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, errmsg + ". Use gettransaction for wallet transactions.");
                QMessageBox Msg_box;
                Msg_box.setText("inValid Transaction"+ QString::fromLocal8Bit(errmsg.c_str()));
                Msg_box.exec();
                return false;
            }
            UniValue result(UniValue::VOBJ);
            UniValue vout(UniValue::VARR);
            const CTransaction &tx = *txone;
            string hexconverted = "";
            bool is_op_return_trans = false;

            for (unsigned int i = 0; i < tx.vout.size(); i++) {
                const CTxOut &txout = tx.vout[i];
                UniValue out(UniValue::VOBJ);
                UniValue o(UniValue::VOBJ);
                ScriptPubKeyToUniv(txout.scriptPubKey, o, true);

                txnouttype type;
                std::vector <CTxDestination> addresses;
                int nRequired;
                std::string asmstring = ScriptToAsmStr(txout.scriptPubKey);
                std::vector <std::string> no_keys = explode_raw_send(" ", asmstring);

                if (!is_op_return_trans) {
                    if (no_keys[0] == "OP_RETURN") {
                        hexconverted = hexToString_send(no_keys[1]);

                        std::string mlc = hexconverted.substr(0, 3);
                        std::string KoT = hexconverted.substr(3, 1);

                        std::string key = hexconverted.substr(4, 34);
                        std::string value = hexconverted.substr(38, 34);

                        if (mlc == "MLC") {
                            if (KoT == "K") {
                                std::string std_data_dir = GetDataDir().string();
                                leveldb::Status status;
                                leveldb::DB *db;
                                leveldb::Options options;
                                options.create_if_missing = true;
                                std::string valueToCheck = "";

                                status = leveldb::DB::Open(options, std_data_dir + "/mlc", &db);
                                if (status.ok()) status = db->Get(leveldb::ReadOptions(), key, &valueToCheck);
                                delete db;
                                if (valueToCheck == "") {
                                    QMessageBox Msg_box;
                                    Msg_box.setText("This key is Not Valid please add a valid key");
                                    Msg_box.exec();
                                    return false;
                                } else {
                                    valueToSave = key;
                                    is_op_return_trans = true;
                                }
                            } else {
                                QMessageBox Msg_box;
                                Msg_box.setText("This key is Not Valid please add a valid key");
                                Msg_box.exec();
                                return false;
                            }
                        } else {
                            QMessageBox Msg_box;
                            Msg_box.setText("This key is Not Valid please add a valid key");
                            Msg_box.exec();
                            return false;
                        }
                    } else {
                        QMessageBox Msg_box;
                        Msg_box.setText("This key is Not Valid please add a valid key");
                        Msg_box.exec();
                        return false;
                    }
                }
            }

            std::shared_ptr <CWallet> wallet = GetWallet(wallet_name);
            CWallet *const pwallet = wallet.get();

            int nMinDepth = 1;
            int nMaxDepth = 9999999;
            std::set <CTxDestination> destinations;
            bool include_unsafe = true;
            CAmount nMinimumAmount = 0;
            CAmount nMaximumAmount = MAX_MONEY;
            CAmount nMinimumSumAmount = MAX_MONEY;
            uint64_t nMaximumCount = 0;

            std::vector <COutput> vecOutputs;
            {
                auto locked_chain = pwallet->chain().lock();
                LOCK2(cs_main, pwallet->cs_wallet);
                pwallet->AvailableCoins(*locked_chain,vecOutputs, !include_unsafe, nullptr, nMinimumAmount, nMaximumAmount,
                                        nMinimumSumAmount,
                                        nMaximumCount, nMinDepth, nMaxDepth);
            }
            uint256 txid;
            CScript scriptpubkeymine;
            CAmount amountdeduct;
            std::string mlcAddress = "";
            int voutunspent = 0;

            for (const COutput &out : vecOutputs) {
                CTxDestination address;
                const CScript &scriptPubKey = out.tx->tx->vout[out.i].scriptPubKey;
                bool fValidAddress = ExtractDestination(scriptPubKey, address);
                if (destinations.size() && (!fValidAddress || !destinations.count(address)))
                    continue;

                voutunspent = out.i;

                scriptpubkeymine = scriptPubKey;
                txid = out.tx->GetHash();

                if (fValidAddress) {
                    mlcAddress = EncodeDestination(address);
                }
                amountdeduct = out.tx->tx->vout[out.i].nValue - 2680;

                if (!IsValidDestination(address)) {
                    QMessageBox Msg_box;
                    Msg_box.setText("Invalid Nexalt address");
                    Msg_box.exec();
                    return false;
                }
                auto keyid = GetKeyForDestination(*pwallet, address);
                if (keyid.IsNull()) {
                    QMessageBox Msg_box;
                    Msg_box.setText("Address does not refer to a key");
                    Msg_box.exec();
                    return false;
                }
                CKey vchSecret;
                if (!pwallet->GetKey(keyid, vchSecret)) {
                    QMessageBox Msg_box;
                    Msg_box.setText("Private key for address is not known");
                    Msg_box.exec();
                    return false;
                }
            }

            CMutableTransaction rawTx;
            int nOutput = voutunspent;
            uint32_t nSequence;
            nSequence = std::numeric_limits<uint32_t>::max();
            CTxIn in(COutPoint(txid, nOutput), CScript(), nSequence);
            rawTx.vin.push_back(in);

            //creating users sponsor ship key
            CPubKey newKey;
            if (!pwallet->GetKeyFromPool(newKey)) {
                QMessageBox Msg_box;
                Msg_box.setText("Keypool ran out, please call keypoolrefill first");
                Msg_box.exec();
                return false;
            }
            OutputType output_type = OutputType::LEGACY;
            pwallet->LearnRelatedScripts(newKey, output_type);
            CTxDestination dest = GetDestinationForKey(newKey, output_type);
            std::string key = EncodeDestination(dest);

            for (int i = 0; i < 2; i++) {
                if (i == 0) {
                    std::string datatostore = key;
                    std::string mlcDataStore = "MLCK" + datatostore + valueToSave;
                    std::string hexDataToStore = stringToHex_send(mlcDataStore);
                    std::vector<unsigned char> data = ParseHexV(hexDataToStore, "Data");
                    CTxOut out(0, CScript() << OP_RETURN << data);
                    rawTx.vout.push_back(out);
                } else {
                    CAmount nAmount = amountdeduct;
                    CTxOut out(nAmount, scriptpubkeymine);
                    rawTx.vout.push_back(out);
                }
            }

            std::string rawtransaction = EncodeHexTx(CTransaction(rawTx));

            //raw transaction created and now signing raw transactiomn
            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, rawtransaction, true)) {
                QMessageBox Msg_box;
                Msg_box.setText("TX decode failed");
                Msg_box.exec();
                return false;
            }

            CCoinsView viewDummy;
            CCoinsViewCache view(&viewDummy);
            {
                LOCK2(cs_main, mempool.cs);
                CCoinsViewCache &viewChain = *pcoinsTip;
                CCoinsViewMemPool viewMempool(&viewChain, mempool);
                view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view
                for (const CTxIn &txin : mtx.vin) {
                    view.AccessCoin(txin.prevout); // Load entries from viewChain into view; can fail.
                }
                view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
            }

            int nHashType = ParseSighashString("ALL");

            bool fHashSingle = ((nHashType & ~SIGHASH_ANYONECANPAY) == SIGHASH_SINGLE);
            // Script verification errors
            UniValue vErrors(UniValue::VARR);
            // Use CTransaction for the constant parts of the
            // transaction to avoid rehashing.
            const CTransaction txConst(mtx);
            // Sign what we can:
            for (unsigned int i = 0; i < mtx.vin.size(); i++) {
                CTxIn &txin = mtx.vin[i];
                const Coin &coin = view.AccessCoin(txin.prevout);
                if (coin.IsSpent()) {
                    QMessageBox Msg_box;
                    Msg_box.setText("Input not found or already spent");
                    Msg_box.exec();
                    return false;
                    //continue;
                }
                const CScript &prevPubKey = coin.out.scriptPubKey;
                const CAmount &amount = coin.out.nValue;

                SignatureData sigdata = DataFromTransaction(mtx, i, coin.out);
                // Only sign SIGHASH_SINGLE if there's a corresponding output:
                if (!fHashSingle || (i < mtx.vout.size())) {
                    ProduceSignature(*pwallet, MutableTransactionSignatureCreator(&mtx, i, amount, nHashType),
                                     prevPubKey,
                                     sigdata);
                }
                UpdateInput(txin, sigdata);

                // amount must be specified for valid segwit signature
                if (amount == MAX_MONEY && !txin.scriptWitness.IsNull()) {
                    throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Missing amount for %s", coin.out.ToString()));
                }
                ScriptError serror = SCRIPT_ERR_OK;
            }
            bool fComplete = vErrors.empty();

            if (!vErrors.empty()) {
                result.pushKV("errors", vErrors);
                QMessageBox Msg_box;
                Msg_box.setText(" Some Error occured");
                Msg_box.exec();
                return false;
            }
            std::promise<void> promise;

            CMutableTransaction mtxtwo;
            if (!DecodeHexTx(mtxtwo, EncodeHexTx(CTransaction(mtx))))
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
            CTransactionRef tx_create(MakeTransactionRef(std::move(mtxtwo)));
            const uint256 &hashTx = tx_create->GetHash();

            CAmount nMaxRawTxFee = maxTxFee;

            nMaxRawTxFee = 0;
            { // cs_main scope
                LOCK(cs_main);
                CCoinsViewCache &view = *pcoinsTip;
                bool fHaveChain = false;
                for (size_t o = 0; !fHaveChain && o < tx_create->vout.size(); o++) {
                    const Coin &existingCoin = view.AccessCoin(COutPoint(hashTx, o));
                    fHaveChain = !existingCoin.IsSpent();
                }
                bool fHaveMempool = mempool.exists(hashTx);
                if (!fHaveMempool && !fHaveChain) {
                    // push to local node and sync with wallets
                    CValidationState state;
                    bool fMissingInputs;
                    if (!AcceptToMemoryPool(mempool, state, std::move(tx_create), &fMissingInputs,
                                            nullptr /* plTxnReplaced */, false /* bypass_limits */, nMaxRawTxFee)) {
                        if (state.IsInvalid()) {
                            throw JSONRPCError(RPC_TRANSACTION_REJECTED, FormatStateMessage(state));
                        } else {
                            if (fMissingInputs) {
                                throw JSONRPCError(RPC_TRANSACTION_ERROR, "Missing inputs");
                            }
                            throw JSONRPCError(RPC_TRANSACTION_ERROR, FormatStateMessage(state));
                        }
                    } else {
                        // If wallet is enabled, ensure that the wallet has been made aware
                        // of the new transaction prior to returning. This prevents a race
                        // where a user might call sendrawtransaction with a transaction
                        // to/from their wallet, immediately call some wallet RPC, and get
                        // a stale result because callbacks have not yet been processed.
                        CallFunctionInValidationInterfaceQueue([&promise] {
                            promise.set_value();
                        });
                    }
                } else if (fHaveChain) {
                    throw JSONRPCError(RPC_TRANSACTION_ALREADY_IN_CHAIN, "transaction already in block chain");
                } else {
                    // Make sure we don't block forever if re-sending
                    // a transaction already in mempool.
                    promise.set_value();
                }

            } // cs_main
            promise.get_future().wait();

            if (!g_connman)
                throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

            CInv inv(MSG_TX, hashTx);
            g_connman->ForEachNode([&inv](CNode *pnode) {
                pnode->PushInventory(inv);
            });
            std::string KeyFound = hashTx.GetHex();
            QMessageBox Msg_box;
            Msg_box.setText("Key: " +QString::fromLocal8Bit(KeyFound.c_str()) );
            Msg_box.exec();
            return true;
        }
    }else{
        return false;
    }
}

void SendCoinsDialog::clear()
{
    // Clear coin control settings
    CoinControlDialog::coinControl()->UnSelectAll();
    ui->checkBoxCoinControlChange->setChecked(false);
    ui->lineEditCoinControlChange->clear();
    coinControlUpdateLabels();

    // Remove entries until only one left
    while(ui->entries->count())
    {
        ui->entries->takeAt(0)->widget()->deleteLater();
    }
    addEntry();

    updateTabsAndLabels();
}

void SendCoinsDialog::reject()
{
    clear();
}

void SendCoinsDialog::accept()
{
    clear();
}

SendCoinsEntry *SendCoinsDialog::addEntry()
{
    SendCoinsEntry *entry = new SendCoinsEntry(platformStyle, this);
    entry->setModel(model);
    ui->entries->addWidget(entry);
    connect(entry, &SendCoinsEntry::removeEntry, this, &SendCoinsDialog::removeEntry);
    connect(entry, &SendCoinsEntry::useAvailableBalance, this, &SendCoinsDialog::useAvailableBalance);
    connect(entry, &SendCoinsEntry::payAmountChanged, this, &SendCoinsDialog::coinControlUpdateLabels);
    connect(entry, &SendCoinsEntry::subtractFeeFromAmountChanged, this, &SendCoinsDialog::coinControlUpdateLabels);

    // Focus the field, so that entry can start immediately
    entry->clear();
    entry->setFocus();
    ui->scrollAreaWidgetContents->resize(ui->scrollAreaWidgetContents->sizeHint());
    qApp->processEvents();
    QScrollBar* bar = ui->scrollArea->verticalScrollBar();
    if(bar)
        bar->setSliderPosition(bar->maximum());

    updateTabsAndLabels();
    return entry;
}

void SendCoinsDialog::updateTabsAndLabels()
{
    setupTabChain(nullptr);
    coinControlUpdateLabels();
}

void SendCoinsDialog::removeEntry(SendCoinsEntry* entry)
{
    entry->hide();

    // If the last entry is about to be removed add an empty one
    if (ui->entries->count() == 1)
        addEntry();

    entry->deleteLater();

    updateTabsAndLabels();
}

QWidget *SendCoinsDialog::setupTabChain(QWidget *prev)
{
    for(int i = 0; i < ui->entries->count(); ++i)
    {
        SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if(entry)
        {
            prev = entry->setupTabChain(prev);
        }
    }
    QWidget::setTabOrder(prev, ui->sendButton);
    QWidget::setTabOrder(ui->sendButton, ui->clearButton);
    QWidget::setTabOrder(ui->clearButton, ui->addButton);
    return ui->addButton;
}

void SendCoinsDialog::setAddress(const QString &address)
{
    SendCoinsEntry *entry = nullptr;
    // Replace the first entry if it is still unused
    if(ui->entries->count() == 1)
    {
        SendCoinsEntry *first = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(0)->widget());
        if(first->isClear())
        {
            entry = first;
        }
    }
    if(!entry)
    {
        entry = addEntry();
    }

    entry->setAddress(address);
}

void SendCoinsDialog::pasteEntry(const SendCoinsRecipient &rv)
{
    if(!fNewRecipientAllowed)
        return;

    SendCoinsEntry *entry = nullptr;
    // Replace the first entry if it is still unused
    if(ui->entries->count() == 1)
    {
        SendCoinsEntry *first = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(0)->widget());
        if(first->isClear())
        {
            entry = first;
        }
    }
    if(!entry)
    {
        entry = addEntry();
    }

    entry->setValue(rv);
    updateTabsAndLabels();
}

bool SendCoinsDialog::handlePaymentRequest(const SendCoinsRecipient &rv)
{
    // Just paste the entry, all pre-checks
    // are done in paymentserver.cpp.
    pasteEntry(rv);
    return true;
}

void SendCoinsDialog::setBalance(const interfaces::WalletBalances& balances)
{
    if(model && model->getOptionsModel())
    {
        ui->labelBalance->setText(BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), balances.balance));
    }
}

void SendCoinsDialog::updateDisplayUnit()
{
    CCoinControl coinControl;
    coinControl.useDarksend = ui->checkUseDarksend->isChecked();
    setBalance(model->wallet().getBalances());
    ui->customFee->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
    updateSmartFeeLabel();
}

void SendCoinsDialog::updateInstanTX()
{
    QSettings settings;
    CCoinControl coinControl;
    settings.setValue("bUseInstanTX", ui->checkInstanTX->isChecked());
    coinControl.useInstanTX = ui->checkInstanTX->isChecked();
    coinControlUpdateLabels();
}

void SendCoinsDialog::processSendCoinsReturn(const WalletModel::SendCoinsReturn &sendCoinsReturn, const QString &msgArg)
{
    QPair<QString, CClientUIInterface::MessageBoxFlags> msgParams;
    // Default to a warning message, override if error message is needed
    msgParams.second = CClientUIInterface::MSG_WARNING;

    // This comment is specific to SendCoinsDialog usage of WalletModel::SendCoinsReturn.
    // WalletModel::TransactionCommitFailed is used only in WalletModel::sendCoins()
    // all others are used only in WalletModel::prepareTransaction()
    switch(sendCoinsReturn.status)
    {
    case WalletModel::InvalidAddress:
        msgParams.first = tr("The recipient address is not valid. Please recheck.");
        break;
    case WalletModel::InvalidAmount:
        msgParams.first = tr("The amount to pay must be larger than 0.");
        break;
    case WalletModel::AmountExceedsBalance:
        msgParams.first = tr("The amount exceeds your balance.");
        break;
    case WalletModel::AmountWithFeeExceedsBalance:
        msgParams.first = tr("The total exceeds your balance when the %1 transaction fee is included.").arg(msgArg);
        break;
    case WalletModel::DuplicateAddress:
        msgParams.first = tr("Duplicate address found: addresses should only be used once each.");
        break;
    case WalletModel::TransactionCreationFailed:
        msgParams.first = tr("Transaction creation failed!");
        msgParams.second = CClientUIInterface::MSG_ERROR;
        break;
    case WalletModel::TransactionCommitFailed:
        msgParams.first = tr("The transaction was rejected with the following reason: %1").arg(sendCoinsReturn.reasonCommitFailed);
        msgParams.second = CClientUIInterface::MSG_ERROR;
        break;
    case WalletModel::AbsurdFee:
        msgParams.first = tr("A fee higher than %1 is considered an absurdly high fee.").arg(BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), model->node().getMaxTxFee()));
        break;
    case WalletModel::PaymentRequestExpired:
        msgParams.first = tr("Payment request expired.");
        msgParams.second = CClientUIInterface::MSG_ERROR;
        break;
    // included to prevent a compiler warning.
    case WalletModel::OK:
    default:
        return;
    }

    Q_EMIT message(tr("Send Coins"), msgParams.first, msgParams.second);
}

void SendCoinsDialog::minimizeFeeSection(bool fMinimize)
{
    ui->labelFeeMinimized->setVisible(fMinimize);
    ui->buttonChooseFee  ->setVisible(fMinimize);
    ui->buttonMinimizeFee->setVisible(!fMinimize);
    ui->frameFeeSelection->setVisible(!fMinimize);
    ui->horizontalLayoutSmartFee->setContentsMargins(0, (fMinimize ? 0 : 6), 0, 0);
    fFeeMinimized = fMinimize;
}

void SendCoinsDialog::on_buttonChooseFee_clicked()
{
    minimizeFeeSection(false);
}

void SendCoinsDialog::on_buttonMinimizeFee_clicked()
{
    updateFeeMinimizedLabel();
    minimizeFeeSection(true);
}

void SendCoinsDialog::useAvailableBalance(SendCoinsEntry* entry)
{
    // Get CCoinControl instance if CoinControl is enabled or create a new one.
    CCoinControl coin_control;
    if (model->getOptionsModel()->getCoinControlFeatures()) {
        coin_control = *CoinControlDialog::coinControl();
    }

    // Calculate available amount to send.
    CAmount amount = model->wallet().getAvailableBalance(coin_control);
    for (int i = 0; i < ui->entries->count(); ++i) {
        SendCoinsEntry* e = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if (e && !e->isHidden() && e != entry) {
            amount -= e->getValue().amount;
        }
    }

    if (amount > 0) {
      entry->checkSubtractFeeFromAmount();
      entry->setAmount(amount);
    } else {
      entry->setAmount(0);
    }
}

void SendCoinsDialog::updateFeeSectionControls()
{
    ui->confTargetSelector      ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelSmartFee           ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelSmartFee2          ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelSmartFee3          ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelFeeEstimation      ->setEnabled(ui->radioSmartFee->isChecked());
    ui->labelCustomFeeWarning   ->setEnabled(ui->radioCustomFee->isChecked());
    ui->labelCustomPerKilobyte  ->setEnabled(ui->radioCustomFee->isChecked());
    ui->customFee               ->setEnabled(ui->radioCustomFee->isChecked());
}

void SendCoinsDialog::updateFeeMinimizedLabel()
{
    if(!model || !model->getOptionsModel())
        return;

    if (ui->radioSmartFee->isChecked())
        ui->labelFeeMinimized->setText(ui->labelSmartFee->text());
    else {
        ui->labelFeeMinimized->setText(BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), ui->customFee->value()) + "/kB");
    }
}

void SendCoinsDialog::updateCoinControlState(CCoinControl& ctrl)
{
    if (ui->radioCustomFee->isChecked()) {
        ctrl.m_feerate = CFeeRate(ui->customFee->value());
    } else {
        ctrl.m_feerate.reset();
    }
    // Avoid using global defaults when sending money from the GUI
    // Either custom fee will be used or if not selected, the confirmation target from dropdown box
    ctrl.m_confirm_target = getConfTargetForIndex(ui->confTargetSelector->currentIndex());
    // Nexalt: Disable RBF GUI
    // ctrl.m_signal_bip125_rbf = ui->optInRBF->isChecked();
}

void SendCoinsDialog::updateSmartFeeLabel()
{
    if(!model || !model->getOptionsModel())
        return;
    CCoinControl coin_control;
    updateCoinControlState(coin_control);
    coin_control.m_feerate.reset(); // Explicitly use only fee estimation rate for smart fee labels
    int returned_target;
    FeeReason reason;
    CFeeRate feeRate = CFeeRate(model->wallet().getMinimumFee(1000, coin_control, &returned_target, &reason));

    ui->labelSmartFee->setText(BitcoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), feeRate.GetFeePerK()) + "/kB");

    if (reason == FeeReason::FALLBACK) {
        ui->labelSmartFee2->show(); // (Smart fee not initialized yet. This usually takes a few blocks...)
        ui->labelFeeEstimation->setText("");
        ui->fallbackFeeWarningLabel->setVisible(true);
        int lightness = ui->fallbackFeeWarningLabel->palette().color(QPalette::WindowText).lightness();
        QColor warning_colour(255 - (lightness / 5), 176 - (lightness / 3), 48 - (lightness / 14));
        ui->fallbackFeeWarningLabel->setStyleSheet("QLabel { color: " + warning_colour.name() + "; }");
        ui->fallbackFeeWarningLabel->setIndent(QFontMetrics(ui->fallbackFeeWarningLabel->font()).width("x"));
    }
    else
    {
        ui->labelSmartFee2->hide();
        ui->labelFeeEstimation->setText(tr("Estimated to begin confirmation within %n block(s).", "", returned_target));
        ui->fallbackFeeWarningLabel->setVisible(false);
    }

    updateFeeMinimizedLabel();
}

// Coin Control: copy label "Quantity" to clipboard
void SendCoinsDialog::coinControlClipboardQuantity()
{
    GUIUtil::setClipboard(ui->labelCoinControlQuantity->text());
}

// Coin Control: copy label "Amount" to clipboard
void SendCoinsDialog::coinControlClipboardAmount()
{
    GUIUtil::setClipboard(ui->labelCoinControlAmount->text().left(ui->labelCoinControlAmount->text().indexOf(" ")));
}

// Coin Control: copy label "Fee" to clipboard
void SendCoinsDialog::coinControlClipboardFee()
{
    GUIUtil::setClipboard(ui->labelCoinControlFee->text().left(ui->labelCoinControlFee->text().indexOf(" ")).replace(ASYMP_UTF8, ""));
}

// Coin Control: copy label "After fee" to clipboard
void SendCoinsDialog::coinControlClipboardAfterFee()
{
    GUIUtil::setClipboard(ui->labelCoinControlAfterFee->text().left(ui->labelCoinControlAfterFee->text().indexOf(" ")).replace(ASYMP_UTF8, ""));
}

// Coin Control: copy label "Bytes" to clipboard
void SendCoinsDialog::coinControlClipboardBytes()
{
    GUIUtil::setClipboard(ui->labelCoinControlBytes->text().replace(ASYMP_UTF8, ""));
}

// Coin Control: copy label "Dust" to clipboard
void SendCoinsDialog::coinControlClipboardLowOutput()
{
    GUIUtil::setClipboard(ui->labelCoinControlLowOutput->text());
}

// Coin Control: copy label "Change" to clipboard
void SendCoinsDialog::coinControlClipboardChange()
{
    GUIUtil::setClipboard(ui->labelCoinControlChange->text().left(ui->labelCoinControlChange->text().indexOf(" ")).replace(ASYMP_UTF8, ""));
}

// Coin Control: settings menu - coin control enabled/disabled by user
void SendCoinsDialog::coinControlFeatureChanged(bool checked)
{
    ui->frameCoinControl->setVisible(checked);

    if (!checked && model) // coin control features disabled
        CoinControlDialog::coinControl()->SetNull();

    coinControlUpdateLabels();
}

// Coin Control: button inputs -> show actual coin control dialog
void SendCoinsDialog::coinControlButtonClicked()
{
    CoinControlDialog dlg(platformStyle);
    dlg.setModel(model);
    dlg.exec();
    coinControlUpdateLabels();
}

// Coin Control: checkbox custom change address
void SendCoinsDialog::coinControlChangeChecked(int state)
{
    if (state == Qt::Unchecked)
    {
        CoinControlDialog::coinControl()->destChange = CNoDestination();
        ui->labelCoinControlChangeLabel->clear();
    }
    else
        // use this to re-validate an already entered address
        coinControlChangeEdited(ui->lineEditCoinControlChange->text());

    ui->lineEditCoinControlChange->setEnabled((state == Qt::Checked));
}

// Coin Control: custom change address changed
void SendCoinsDialog::coinControlChangeEdited(const QString& text)
{
    if (model && model->getAddressTableModel())
    {
        // Default to no change address until verified
        CoinControlDialog::coinControl()->destChange = CNoDestination();
        ui->labelCoinControlChangeLabel->setStyleSheet("QLabel{color:red;}");

        const CTxDestination dest = DecodeDestination(text.toStdString());

        if (text.isEmpty()) // Nothing entered
        {
            ui->labelCoinControlChangeLabel->setText("");
        }
        else if (!IsValidDestination(dest)) // Invalid address
        {
            ui->labelCoinControlChangeLabel->setText(tr("Warning: Invalid Nexalt address"));
        }
        else // Valid address
        {
            if (!model->wallet().isSpendable(dest)) {
                ui->labelCoinControlChangeLabel->setText(tr("Warning: Unknown change address"));

                // confirmation dialog
                QMessageBox::StandardButton btnRetVal = QMessageBox::question(this, tr("Confirm custom change address"), tr("The address you selected for change is not part of this wallet. Any or all funds in your wallet may be sent to this address. Are you sure?"),
                    QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel);

                if(btnRetVal == QMessageBox::Yes)
                    CoinControlDialog::coinControl()->destChange = dest;
                else
                {
                    ui->lineEditCoinControlChange->setText("");
                    ui->labelCoinControlChangeLabel->setStyleSheet("QLabel{color:black;}");
                    ui->labelCoinControlChangeLabel->setText("");
                }
            }
            else // Known change address
            {
                ui->labelCoinControlChangeLabel->setStyleSheet("QLabel{color:black;}");

                // Query label
                QString associatedLabel = model->getAddressTableModel()->labelForAddress(text);
                if (!associatedLabel.isEmpty())
                    ui->labelCoinControlChangeLabel->setText(associatedLabel);
                else
                    ui->labelCoinControlChangeLabel->setText(tr("(no label)"));

                CoinControlDialog::coinControl()->destChange = dest;
            }
        }
    }
}

// Coin Control: update labels
void SendCoinsDialog::coinControlUpdateLabels()
{
    if (!model || !model->getOptionsModel())
        return;

    updateCoinControlState(*CoinControlDialog::coinControl());

    // set pay amounts
    CoinControlDialog::payAmounts.clear();
    CoinControlDialog::fSubtractFeeFromAmount = false;

    for(int i = 0; i < ui->entries->count(); ++i)
    {
        SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if(entry && !entry->isHidden())
        {
            SendCoinsRecipient rcp = entry->getValue();
            CoinControlDialog::payAmounts.append(rcp.amount);
            if (rcp.fSubtractFeeFromAmount)
                CoinControlDialog::fSubtractFeeFromAmount = true;
        }
    }

    if (CoinControlDialog::coinControl()->HasSelected())
    {
        // actual coin control calculation
        CoinControlDialog::updateLabels(model, this);

        // show coin control stats
        ui->labelCoinControlAutomaticallySelected->hide();
        ui->widgetCoinControl->show();
    }
    else
    {
        // hide coin control stats
        ui->labelCoinControlAutomaticallySelected->show();
        ui->widgetCoinControl->hide();
        ui->labelCoinControlInsuffFunds->hide();
    }
}

SendConfirmationDialog::SendConfirmationDialog(const QString &title, const QString &text, int _secDelay,
    QWidget *parent) :
    QMessageBox(QMessageBox::Question, title, text, QMessageBox::Yes | QMessageBox::Cancel, parent), secDelay(_secDelay)
{
    setDefaultButton(QMessageBox::Cancel);
    yesButton = button(QMessageBox::Yes);
    updateYesButton();
    connect(&countDownTimer, &QTimer::timeout, this, &SendConfirmationDialog::countDown);
}

int SendConfirmationDialog::exec()
{
    updateYesButton();
    countDownTimer.start(1000);
    return QMessageBox::exec();
}

void SendConfirmationDialog::countDown()
{
    secDelay--;
    updateYesButton();

    if(secDelay <= 0)
    {
        countDownTimer.stop();
    }
}

void SendConfirmationDialog::updateYesButton()
{
    if(secDelay > 0)
    {
        yesButton->setEnabled(false);
        yesButton->setText(tr("Yes") + " (" + QString::number(secDelay) + ")");
    }
    else
    {
        yesButton->setEnabled(true);
        yesButton->setText(tr("Yes"));
    }
}
