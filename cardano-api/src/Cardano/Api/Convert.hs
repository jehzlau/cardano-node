module Cardano.Api.Convert
  ( ConversionError
  , addressFromHex
  , addressToHex
  , convertITNpublicKey
  , convertITNsigningKey
  , parseTxIn
  , parseTxOut
  , readText
  , renderConversionError
  , renderTxIn
  , renderTxOut
  ) where

import           Cardano.Api.Error (textShow)
import           Cardano.Api.Types
import qualified Cardano.Binary as Binary
import           Cardano.Prelude
import           Prelude (String)

import           Control.Exception (IOException)
import qualified Control.Exception as Exception
import           Control.Monad.Fail (fail)

import qualified Codec.Binary.Bech32 as Bech32
import           Data.Attoparsec.ByteString.Char8 (Parser)
import qualified Data.Attoparsec.ByteString.Char8 as Atto
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Char8 as C8
import           Data.Char (isAlphaNum)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text

import qualified Cardano.Crypto.DSIGN as DSIGN
import qualified Cardano.Crypto.Hash.Class as Crypto
import qualified Cardano.Crypto.Hash.Blake2b as Crypto

import qualified Shelley.Spec.Ledger.Address as Shelley
import qualified Shelley.Spec.Ledger.Keys as Shelley

data ConversionError
  = Bech32DecodingError !FilePath !Bech32.DecodingError
  | ITNErr !Text
  | SigningKeyDeserializationError !ByteString
  | VerificationKeyDeserializationError !ByteString
  deriving Show

renderConversionError :: ConversionError -> Text
renderConversionError err =
  case err of
    Bech32DecodingError fp decErr ->
      "Error decoding Bech32 key at:" <> textShow fp <> " Error: " <> textShow decErr
    ITNErr errMessage -> errMessage
    SigningKeyDeserializationError sKey ->
      "Error deserialising signing key: " <> textShow (C8.unpack sKey)
    VerificationKeyDeserializationError vKey ->
      "Error deserialising verification key: " <> textShow (C8.unpack vKey)

addressFromHex :: Text -> Maybe Address
addressFromHex txt =
  case Base16.decode (Text.encodeUtf8 txt) of
    (raw, _) ->
      case Shelley.deserialiseAddr raw of
        Just addr -> Just $ AddressShelley addr
        Nothing -> either (const Nothing) (Just . AddressByron) $ Binary.decodeFull' raw

addressToHex :: Address -> Text
addressToHex addr =
  -- Text.decodeUtf8 theoretically can throw an exception but should never
  -- do so on Base16 encoded data.
  Text.decodeUtf8 . Base16.encode $
    case addr of
      AddressByron ba -> Binary.serialize' ba
      AddressShelley sa -> Shelley.serialiseAddr sa
      AddressShelleyReward sRwdAcct -> Binary.serialize' sRwdAcct

parseTxIn :: Text -> Either String TxIn
parseTxIn txt = Atto.parseOnly pTxIn $ Text.encodeUtf8 txt

parseTxOut :: Text -> Maybe TxOut
parseTxOut =
  either (const Nothing) Just . Atto.parseOnly pTxOut . Text.encodeUtf8

renderTxIn :: TxIn -> Text
renderTxIn (TxIn (TxId txid) txix) =
  mconcat
    [ Text.decodeUtf8 (Crypto.getHashBytesAsHex txid)
    , "#"
    , Text.pack (show txix)
    ]

renderTxOut :: TxOut -> Text
renderTxOut (TxOut addr ll) =
  mconcat
    [ addressToHex addr
    , "+"
    , Text.pack (show ll)
    ]

pTxIn :: Parser TxIn
pTxIn = TxIn <$> pTxId <*> (Atto.char '#' *> Atto.decimal)

pTxId :: Parser TxId
pTxId = TxId <$> pCBlakeHash

pCBlakeHash :: Parser (Crypto.Hash Crypto.Blake2b_256 ())
pCBlakeHash = do
   potentialHex <- pAlphaNumToByteString
   resultHash <- return $ Crypto.hashFromBytesAsHex potentialHex
   case resultHash of
     Nothing -> handleHexParseFailure potentialHex $ Atto.parseOnly pAddress potentialHex
     Just hash -> return hash
  where
   -- We fail in both cases: 1) The input is not hex encoded 2) A user mistakenly enters an address
   handleHexParseFailure :: ByteString -> Either String Address -> Parser (Crypto.Hash Crypto.Blake2b_256 ())
   handleHexParseFailure input (Left _) = fail $ "Your input is either malformed or not hex encoded: " ++ C8.unpack input
   handleHexParseFailure _ (Right _) = fail $ " You have entered an address, please enter a tx input"

pTxOut :: Parser TxOut
pTxOut =
  TxOut <$> pAddress <* Atto.char '+' <*> pLovelace

pLovelace :: Parser Lovelace
pLovelace = Lovelace <$> Atto.decimal

pAddress :: Parser Address
pAddress =
  maybe (fail "pAddress") pure
    =<< addressFromHex . Text.decodeUtf8 <$> pAlphaNumToByteString

pAlphaNumToByteString :: Parser ByteString
pAlphaNumToByteString = Atto.takeWhile1 isAlphaNum


-- | Convert public ed25519 key to a Shelley stake verification key
convertITNpublicKey :: Text -> Either ConversionError StakingVerificationKey
convertITNpublicKey pubKey = do
  keyBS <- decodeBech32Key pubKey
  case DSIGN.rawDeserialiseVerKeyDSIGN keyBS of
    Just verKey -> Right . StakingVerificationKeyShelley $ Shelley.VKey verKey
    Nothing -> Left $ VerificationKeyDeserializationError keyBS

-- | Convert private ed22519 key to a Shelley signing key.
convertITNsigningKey :: Text -> Either ConversionError SigningKey
convertITNsigningKey privKey = do
  keyBS <- decodeBech32Key privKey
  case DSIGN.rawDeserialiseSignKeyDSIGN keyBS of
    Just signKey -> Right $ SigningKeyShelley signKey
    Nothing -> Left $ SigningKeyDeserializationError keyBS

-- | Convert ITN Bech32 public or private keys to 'ByteString's
decodeBech32Key :: Text -> Either ConversionError ByteString
decodeBech32Key key =
  case Bech32.decode key of
    Left err -> Left . ITNErr $ textShow err
    Right (_, dataPart) -> case Bech32.dataPartToBytes dataPart of
                             Nothing -> Left $ ITNErr "Error extracting a ByteString from a DataPart: \
                                                      \See bech32 library function: dataPartToBytes"
                             Just bs -> Right bs

readText :: FilePath -> IO (Either Text Text)
readText fp = do
  eStr <- Exception.try $ readFile fp
  case eStr of
    Left e -> return . Left $ handler e
    Right txt -> return $ Right txt
 where
  handler :: IOException -> Text
  handler e = Text.pack $ "Cardano.Api.Convert.readText: "
                     ++ displayException e
