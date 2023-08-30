using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Management;

namespace Ares
{
    enum AppStatus
    {
        Online,
        Offline
    };

    enum AuthResponse
    {
        Valid,
        Invalid,
        HWID,
        Banned,
        Expired
    };


    class App
    {
        public string ID { get; set; }
        public string Name { get; set; }
        public AppStatus Status { get; set; }
    };

    class SecureImage
    {
        public int[] Image { get; set; }
        public int Key { get; set; }

        public int[] Decrypt()
        {
            int[] Decrypted = new int[Image.Length];
            for(int i = 0; i < Image.Length; i++)
            {
                Decrypted[i] = Image[i] ^ Key;
            }
            Array.Reverse(Decrypted);
            return Decrypted;
        }
    }

    class License
    {
        public string ID { get; set; }
        public string HWID { get; set; }
        public string Expiry { get; set; }
        public string LastLogin { get; set; }
        public bool IsBanned { get; set; }
        public string IP { get; set; }
        public int Duration { get; set; }
        public int Status { get; set; }
        public string CreatedOn { get; set; }

        public AppStatus status { get; set; }
    };

    class Ares
    {
        private int ServerSignature = 62463;
        private readonly int[] ServerKey = { 77, 73, 73, 67, 73, 84, 65, 78, 66, 103, 107, 113, 104, 107, 105, 71, 57, 119, 48, 66, 65, 81, 69, 70, 65, 65, 79, 67, 65, 103, 52, 65, 77, 73, 73, 67, 67, 81, 75, 67, 65, 103, 66, 56, 81, 66, 116, 116, 82, 110, 88, 70, 112, 106, 67, 57, 101, 67, 121, 108, 74, 80, 72, 53, 84, 75, 77, 78, 65, 81, 80, 48, 122, 76, 116, 118, 107, 74, 108, 90, 109, 68, 90, 103, 90, 77, 80, 82, 74, 82, 51, 118, 87, 68, 80, 111, 119, 87, 48, 104, 103, 57, 81, 77, 113, 119, 79, 106, 54, 101, 112, 75, 66, 75, 102, 50, 108, 55, 73, 88, 81, 84, 99, 119, 74, 102, 97, 47, 119, 80, 84, 80, 52, 69, 110, 74, 73, 73, 66, 119, 48, 86, 114, 111, 51, 43, 47, 119, 118, 90, 49, 72, 80, 80, 47, 73, 107, 108, 74, 68, 69, 104, 57, 87, 119, 54, 69, 84, 57, 121, 54, 54, 121, 111, 67, 48, 49, 116, 68, 84, 76, 74, 65, 84, 67, 54, 50, 103, 104, 79, 112, 82, 49, 70, 89, 69, 49, 116, 71, 75, 114, 117, 71, 79, 47, 71, 104, 54, 76, 106, 84, 84, 106, 84, 53, 85, 77, 122, 120, 106, 122, 107, 43, 83, 77, 109, 118, 73, 74, 67, 68, 105, 119, 57, 73, 117, 75, 85, 48, 85, 100, 104, 78, 78, 77, 70, 86, 73, 74, 110, 106, 85, 81, 71, 52, 48, 74, 121, 80, 66, 53, 99, 81, 118, 80, 76, 70, 103, 100, 73, 81, 50, 82, 98, 77, 90, 118, 82, 77, 66, 113, 66, 70, 117, 104, 43, 108, 55, 87, 54, 120, 52, 101, 85, 103, 121, 54, 54, 53, 69, 98, 84, 102, 66, 101, 118, 70, 89, 102, 115, 50, 71, 73, 103, 113, 50, 51, 66, 69, 110, 97, 47, 98, 100, 118, 97, 98, 117, 89, 120, 87, 78, 99, 65, 55, 48, 112, 49, 50, 106, 73, 52, 75, 102, 68, 66, 53, 100, 51, 74, 115, 48, 121, 111, 69, 113, 66, 102, 70, 83, 72, 115, 89, 56, 116, 84, 106, 119, 88, 113, 113, 117, 55, 121, 74, 103, 74, 120, 78, 70, 56, 117, 85, 70, 47, 109, 88, 77, 112, 119, 116, 122, 51, 97, 78, 97, 71, 47, 98, 88, 118, 82, 77, 78, 101, 84, 52, 101, 120, 75, 84, 52, 97, 72, 78, 99, 88, 119, 97, 85, 115, 116, 68, 120, 105, 99, 115, 103, 78, 65, 84, 103, 114, 54, 115, 49, 48, 55, 68, 78, 78, 78, 50, 87, 77, 103, 65, 68, 56, 56, 122, 86, 112, 69, 122, 109, 85, 70, 118, 51, 74, 107, 118, 89, 49, 88, 84, 76, 98, 102, 104, 67, 79, 114, 86, 111, 120, 89, 112, 87, 67, 43, 120, 118, 65, 69, 49, 71, 81, 104, 68, 50, 75, 65, 100, 97, 105, 83, 48, 72, 75, 55, 72, 122, 47, 115, 111, 117, 121, 101, 73, 48, 103, 120, 119, 117, 65, 78, 120, 110, 100, 103, 105, 113, 104, 52, 82, 57, 69, 119, 113, 76, 113, 68, 109, 121, 48, 77, 84, 102, 101, 119, 107, 66, 80, 81, 104, 108, 84, 98, 69, 65, 116, 79, 106, 108, 113, 75, 99, 115, 119, 97, 71, 121, 109, 70, 65, 117, 49, 121, 85, 120, 88, 87, 78, 80, 78, 107, 87, 107, 66, 117, 84, 56, 120, 57, 53, 76, 55, 83, 52, 83, 118, 121, 79, 81, 109, 74, 110, 88, 49, 106, 113, 108, 105, 85, 99, 117, 56, 43, 108, 72, 98, 114, 65, 78, 121, 119, 82, 86, 120, 72, 100, 86, 52, 77, 117, 100, 75, 110, 108, 85, 102, 70, 110, 107, 48, 76, 72, 121, 73, 69, 51, 52, 107, 53, 68, 118, 56, 117, 106, 84, 99, 54, 54, 74, 83, 120, 82, 117, 99, 108, 86, 81, 105, 86, 84, 109, 117, 51, 83, 90, 67, 104, 66, 56, 99, 69, 115, 101, 87, 86, 85, 75, 119, 43, 88, 71, 56, 102, 112, 83, 47, 117, 82, 101, 87, 97, 97, 52, 100, 110, 43, 105, 81, 102, 51, 76, 110, 88, 81, 76, 73, 100, 66, 99, 50, 88, 51, 90, 106, 80, 74, 120, 69, 81, 73, 68, 65, 81, 65, 66 };
        private RSA ClientRSA;
        private RSA ServerRSA;
        private string SessionId;

        public bool IsAuthenticated = false;

        public License License;

        public App App;

        private string Encrypt(string Text, RSA Key)
        {
            byte[] Data = Encoding.UTF8.GetBytes(Text);

            byte[] EncryptedData = Key.Encrypt(Data, RSAEncryptionPadding.OaepSHA1);

            return Convert.ToBase64String(EncryptedData);
        }

        private string Decrypt(string Text, RSA Key)
        {
            byte[] Data = Convert.FromBase64String(Text);

            byte[] DecryptedData = Key.Decrypt(Data, RSAEncryptionPadding.OaepSHA1);

            return Encoding.UTF8.GetString(DecryptedData);
        }

        public AppStatus GetAppStatus(int[] AppEncrypted)
        {
            HttpClient HttpClient = new HttpClient();

            string AppId = "";
            for (int i = 0; i < AppEncrypted.Length; i++)
            {
                AppId += ((char)(AppEncrypted[i] ^ ServerSignature)).ToString();
            }

            Task<HttpResponseMessage> RequestTask = Task.Run(() => HttpClient.GetAsync("https://api.ares.lol/status/" + AppId));
            Task<string> ResponseData = Task.Run(() => RequestTask.Result.Content.ReadAsStringAsync());
            Dictionary<string, int> Response = JsonSerializer.Deserialize<Dictionary<string, int>>(ResponseData.Result.ToString());

            if (Response["code"] != 0)
            {
                throw new Exception("Unknown app");
            }

            return (AppStatus)Response["status"];
        }

        public bool Connect(int[] AppEncrypted)
        {
            int Signature = 0;
            for (int i = 0; i < ServerKey.Length; i++)
            {
                Signature += ServerKey[i];
            }

            if (Signature != ServerSignature) return false;

            this.ServerRSA = RSA.Create();

            char[] KeyArray = new char[ServerKey.Length];
            for (int i = 0; i < ServerKey.Length; i++)
            {
                KeyArray[i] = (char)ServerKey[i];
            }

            string PublicKeyString = new string(KeyArray);

            PublicKeyString = "-----BEGIN PUBLIC KEY-----\n" + PublicKeyString + "\n-----END PUBLIC KEY-----";

            this.ServerRSA.ImportFromPem(PublicKeyString);

            PublicKeyString = "";

            this.ClientRSA = RSA.Create();
            this.ClientRSA.KeySize = 4096;


            string publicKeyEncoded = Convert.ToBase64String(ClientRSA.ExportRSAPublicKey());

            HttpClient HttpClient = new HttpClient();

            Dictionary<string, string> RequestData = new Dictionary<string, string>();
            Dictionary<string, int[]> ArrayData = new Dictionary<string, int[]>();

            Int64 key = new Random().NextInt64(0, 99999999);

            int[] encryptedPublicKey = new int[publicKeyEncoded.Length];
            for (int i = 0; i < publicKeyEncoded.Length; i++)
            {
                encryptedPublicKey[i] = publicKeyEncoded[i] ^ (int)key;
            }

            ArrayData["data"] = encryptedPublicKey;

            string AppId = "";
            for (int i = 0; i < AppEncrypted.Length; i++)
            {
                AppId += ((char)(AppEncrypted[i] ^ ServerSignature)).ToString();
            }

            var ManagementObjectSearcher = new ManagementObjectSearcher("Select ProcessorId From Win32_processor");
            ManagementObjectCollection ManagementObjectSearcherList = ManagementObjectSearcher.Get();
            string HardwareId = "";
            foreach (ManagementObject ManagementObject in ManagementObjectSearcherList)
            {
                using (SHA256 sha256 = SHA256.Create())
                {
                    byte[] Hash = sha256.ComputeHash(
                        Encoding.UTF8.GetBytes(ManagementObject["ProcessorId"].ToString())
                        );

                    foreach (byte Byte in Hash)
                    {
                        HardwareId += $"{Byte:X2}".ToLower();
                    }

                }
                break;
            }

            RequestData[Encrypt("hwid", this.ServerRSA)] = Encrypt(HardwareId, this.ServerRSA);
            RequestData[Encrypt("app", this.ServerRSA)] = Encrypt(AppId, this.ServerRSA);
            RequestData[Encrypt("system_time", this.ServerRSA)] = Encrypt(((DateTimeOffset)DateTime.UtcNow).ToUnixTimeSeconds().ToString(), this.ServerRSA);
            RequestData[Encrypt("client_key", this.ServerRSA)] = Encrypt(key.ToString(), this.ServerRSA);
            RequestData[Encrypt("client_public_array", this.ServerRSA)] = JsonSerializer.Serialize(ArrayData);

            JsonContent RequestContent = JsonContent.Create(RequestData);

            Task<HttpResponseMessage> RequestTask = Task.Run(() => HttpClient.PostAsync("http://client-api.ares.lol/api/standard/connect", RequestContent));
            Task<string> ResponseData = Task.Run(() => RequestTask.Result.Content.ReadAsStringAsync());
            Dictionary<string, string> Response = JsonSerializer.Deserialize<Dictionary<string, string>>(ResponseData.Result.ToString());

            Dictionary<string, string> DecryptedBody = new Dictionary<string, string>();

            foreach (KeyValuePair<string, string> Entry in Response)
            {
                DecryptedBody[Decrypt(Entry.Key, ClientRSA)] = Decrypt(Entry.Value, ClientRSA);
            }

            this.SessionId = DecryptedBody["session"];
            var options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            };
            this.App = JsonSerializer.Deserialize<App>(DecryptedBody["app"], options);

            return true;
        }
    
        public AuthResponse Authenticate(string LicenseStr)
        {
            HttpClient HttpClient = new HttpClient();
            Dictionary<string, string> RequestData = new Dictionary<string, string>();

            RequestData[Encrypt("session", this.ServerRSA)] = Encrypt(this.SessionId, this.ServerRSA);
            RequestData[Encrypt("app", this.ServerRSA)] = Encrypt(this.App.ID, this.ServerRSA);
            RequestData[Encrypt("license", this.ServerRSA)] = Encrypt(LicenseStr, this.ServerRSA);

            JsonContent RequestContent = JsonContent.Create(RequestData);

            Task<HttpResponseMessage> RequestTask = Task.Run(() => HttpClient.PostAsync("http://client-api.ares.lol/api/standard/vector", RequestContent));
            Task<string> ResponseData = Task.Run(() => RequestTask.Result.Content.ReadAsStringAsync());
            Dictionary<string, string> Response = JsonSerializer.Deserialize<Dictionary<string, string>>(ResponseData.Result.ToString());


            Dictionary<string, string> DecryptedBody = new Dictionary<string, string>();

            foreach (KeyValuePair<string, string> Entry in Response)
            {
                DecryptedBody[Decrypt(Entry.Key, ClientRSA)] = Decrypt(Entry.Value, ClientRSA);
            }

            if (DecryptedBody["authenticated"] == "true")
            {
                this.IsAuthenticated = true;

                this.License = new License();

                this.License.ID = LicenseStr;
                this.License.HWID = DecryptedBody["hwid"];
                this.License.Expiry = DecryptedBody["expiry"];
                this.License.LastLogin = DecryptedBody["lastLogin"];
                this.License.IsBanned = false;
                this.License.IP = DecryptedBody["ip"];
                this.License.Duration = Int32.Parse(DecryptedBody["duration"]);
                this.License.Status = Int32.Parse(DecryptedBody["status"]);
                this.License.CreatedOn = DecryptedBody["created_on"];

                return AuthResponse.Valid;
            }

            switch(DecryptedBody["reason"])
            {
                case "hwid":
                    return AuthResponse.HWID;
                case "banned":
                    return AuthResponse.Banned;
                case "expired":
                    return AuthResponse.Expired;
                default:
                    return AuthResponse.Invalid;
            }
        }

        public string Variable(string Name)
        {
            if(!IsAuthenticated)
            {
                throw new Exception("Not authenticated!");
            }

            HttpClient HttpClient = new HttpClient();
            Dictionary<string, string> RequestData = new Dictionary<string, string>();

            RequestData[Encrypt("session", this.ServerRSA)] = Encrypt(this.SessionId, this.ServerRSA);
            RequestData[Encrypt("app", this.ServerRSA)] = Encrypt(this.App.ID, this.ServerRSA);
            RequestData[Encrypt("name", this.ServerRSA)] = Encrypt(Name, this.ServerRSA);

            JsonContent RequestContent = JsonContent.Create(RequestData);

            Task<HttpResponseMessage> RequestTask = Task.Run(() => HttpClient.PostAsync("http://client-api.ares.lol/api/standard/variable", RequestContent));
            Task<string> ResponseData = Task.Run(() => RequestTask.Result.Content.ReadAsStringAsync());
            Dictionary<string, string> Response = JsonSerializer.Deserialize<Dictionary<string, string>>(ResponseData.Result.ToString());


            Dictionary<string, string> DecryptedBody = new Dictionary<string, string>();

            foreach (KeyValuePair<string, string> Entry in Response)
            {
                DecryptedBody[Decrypt(Entry.Key, ClientRSA)] = Decrypt(Entry.Value, ClientRSA);
            }

            return DecryptedBody["content"];
        }

        public SecureImage Module(string Module)
        {
            if (!IsAuthenticated)
            {
                throw new Exception("Not authenticated!");
            }

            HttpClient HttpClient = new HttpClient();
            Dictionary<string, string> RequestData = new Dictionary<string, string>();

            RequestData[Encrypt("session", this.ServerRSA)] = Encrypt(this.SessionId, this.ServerRSA);
            RequestData[Encrypt("app", this.ServerRSA)] = Encrypt(this.App.ID, this.ServerRSA);
            RequestData[Encrypt("module", this.ServerRSA)] = Encrypt(Module, this.ServerRSA);

            JsonContent RequestContent = JsonContent.Create(RequestData);

            Task<HttpResponseMessage> RequestTask = Task.Run(() => HttpClient.PostAsync("http://client-api.ares.lol/api/standard/module", RequestContent));
            Task<string> ResponseData = Task.Run(() => RequestTask.Result.Content.ReadAsStringAsync());
            Dictionary<string, object> Response = JsonSerializer.Deserialize<Dictionary<string, object>>(ResponseData.Result.ToString());

            Dictionary<string, string> DecryptedBody = new Dictionary<string, string>();
            int[] ImageData = new int[] { 1, 2, 3, 4 };

            foreach (var Entry in Response.Keys)
            {
                string Header = Decrypt(Entry, ClientRSA);
                if(Header.Contains("array"))
                {
                    if(!Header.Contains("fake"))
                    {
                        ImageData = JsonSerializer.Deserialize<int[]>(Response[Entry].ToString());
                    }
                }
                else
                {
                    DecryptedBody[Header] = Decrypt(Response[Entry].ToString(), ClientRSA);

                }
            }

            SecureImage SecureImage = new SecureImage();
            SecureImage.Image = ImageData;
            SecureImage.Key = Int32.Parse(DecryptedBody["key"]);

            return SecureImage;
        }
    };
}
