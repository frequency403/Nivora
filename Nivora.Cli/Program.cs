using Nivora.Core;
using Nivora.Core.Models;

namespace Nivora.Cli;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine(Argon2Hash.Hash("yourMomGhey", new Salt()));
    }
}