using System;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Identity.Client; // `dotnet add package Microsoft.Identity.Client --version 4.39.0`
using System.Net.Http.Headers;
using System.IdentityModel.Tokens.Jwt;  // dotnet add package System.IdentityModel.Tokens.Jwt --version 6.8.0
using System.Runtime.CompilerServices;
using System.Collections.Generic;
using System.IO;
using Azure.Identity;  // dotnet add package Azure.Identity
using Microsoft.Graph; // dotnet add package Microsoft.Graph

class Program
{
    static async Task Main(string[] args)
    {
        var envDict = LoadEnv();
        foreach (KeyValuePair<string, string> kvp in envDict)
        {
            Console.WriteLine($"Key: {kvp.Key}, Value: {kvp.Value}");
        }

        string clientId = envDict["CLIENT_ID"];
        string authority = envDict["AUTHORITY"];
        string tenantId = envDict["TENANT_ID"];
        string clientSecret = envDict["CLIENT_SECRET"];

        // 接続用クライアントを作成
        var app = PublicClientApplicationBuilder.Create(clientId).WithAuthority(authority).WithRedirectUri("http://localhost").Build();

        string token = await AcquireTokenAsync(app);
        PrintDecodedToken(token);

        // c => c.Type == "scp" は、c.Type が "scp" と等しい場合に true を返すラムダ式
        JwtSecurityToken jwtToken = new JwtSecurityToken(token);
        string scopes = jwtToken.Claims.First(c => c.Type == "scp").Value;
        var roles = jwtToken.Claims.Where(c => c.Type == "roles").Select(c => c.Value).ToList();
        Console.WriteLine($"\n scopes:{scopes} ");
        Console.WriteLine("Roles: " + string.Join(", ", roles));


        HttpClient httpClient = new HttpClient();
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        // Graph Client 作成
        // このスコープは、Azure AD のアプリケーションの API アクセス許可で設定したものを取得する特別なURI
        var graph_scopes = new[] { "https://graph.microsoft.com/.default" };

        // using Azure.Identity;
        var options = new ClientSecretCredentialOptions
        {
            AuthorityHost = AzureAuthorityHosts.AzurePublicCloud,
        };

        // https://learn.microsoft.com/dotnet/api/azure.identity.clientsecretcredential
        var clientSecretCredential = new ClientSecretCredential(
            tenantId, clientId, clientSecret, options);

        var graphClient = new GraphServiceClient(clientSecretCredential, graph_scopes);

        bool anyScopeFound = false;
        if (roles.Contains("Task.Scope1") && scopes.Contains("scope1"))
        {
            // scope1 Graph で入力したオブジェクトIDのユーザー情報を取得
            anyScopeFound = true;
            Console.WriteLine("This is scope1. Please enter the object ID of the user you want to fetch:");
            string objectId = Console.ReadLine();
            var user = await graphClient.Users[$"{objectId}"].GetAsync();
            Console.WriteLine($"Hello, this is scope1. The user you are looking for is {user.DisplayName}.");
        }
        if (roles.Contains("Task.Scope2") && scopes.Contains("scope2"))
        {
            anyScopeFound = true;
            Console.WriteLine("HEllo, this is scope2");
        }
        if (!anyScopeFound)
        {
            Console.WriteLine("Hello, this is no scope");
        }

    }

    static async Task<string> AcquireTokenAsync(IPublicClientApplication app)
    {
        var scopes = new[] { "api://92eb6243-7ae1-4949-a9ea-90634cbf0ee8/scope1", "api://92eb6243-7ae1-4949-a9ea-90634cbf0ee8/scope2" };
        var result = await app.AcquireTokenInteractive(scopes).ExecuteAsync();
        return result.AccessToken;
    }

    static bool HasRequiredScope(string token, string requriedScope)
    {
        var handler = new JwtSecurityTokenHandler();
        var decodedToken = handler.ReadJwtToken(token);

        if (decodedToken.Claims == null)
        {
            return false;
        }

        foreach (var claim in decodedToken.Claims)
        {
            if (claim.Type == "scp" && claim.Type == "http://schemas.microsoft.com/identity/claims/scope")
            {
                string[] scopes = claim.Value.Split(' ');
                foreach (var scope in scopes)
                {
                    if (scope == requriedScope)
                    {
                        return true;
                    }
                }
            }
        }

        return false;

    }

    static void PrintDecodedToken(string token)
    {
        var jwtToken = new JwtSecurityToken(token);

        Console.WriteLine("JWT Header:");
        foreach (var header in jwtToken.Header)
        {
            Console.WriteLine($"{header.Key}: {header.Value}");
        }

        Console.WriteLine("JWT Payload:");
        foreach (var claim in jwtToken.Claims)
        {
            Console.WriteLine($"{claim.Type}: {claim.Value}");
        }
    }

    static Dictionary<string, string> LoadEnv()
    {
        var envVars = new Dictionary<string, string>();
        var lines = File.ReadAllLines(".env");

        foreach (var line in lines)
        {
            var parts = line.Split('=', 2);
            if (parts.Length == 2)
            {
                envVars[parts[0].Trim('"')] = parts[1].Trim('"');
            }
        }
        return envVars;
    }
}
