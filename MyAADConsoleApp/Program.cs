using System;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Identity.Client;
using System.Net.Http.Headers;
using System.IdentityModel.Tokens.Jwt;  // dotnet add package System.IdentityModel.Tokens.Jwt --version 6.8.0
using System.Runtime.CompilerServices;
using System.Collections.Generic;
using System.IO;

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

        // 接続用クライアントを作成
        var app = PublicClientApplicationBuilder.Create(clientId).WithAuthority(authority).WithRedirectUri("http://localhost").Build();

        string token = await AcquireTokenAsync(app);
        PrintDecodedToken(token);

        // c => c.Type == "scp" は、c.Type が "scp" と等しい場合に true を返すラムダ式
        JwtSecurityToken jwtToken = new JwtSecurityToken(token);
        string scopes = jwtToken.Claims.First(c => c.Type == "scp").Value;
        Console.WriteLine($"\n scopes:{scopes} ");

        HttpClient httpClient = new HttpClient();
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        bool anyScopeFound = false;
        if (scopes.Contains("scope1"))
        {
            anyScopeFound = true;
            Console.WriteLine("Hello, this is scope1");
        }
        if (scopes.Contains("scope2"))
        {
            anyScopeFound = true;
            Console.WriteLine("Hello, this is scope2");
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
