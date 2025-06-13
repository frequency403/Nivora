using Nivora.Core;
using Nivora.Core.Models;

namespace Nivora.Cli;

class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine(await Argon2Hash.HashBase64("yourMomGhey"));
    }
}