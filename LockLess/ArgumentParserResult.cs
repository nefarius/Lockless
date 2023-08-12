using System.Collections.Generic;

namespace LockLess;

public class ArgumentParserResult
{
    private ArgumentParserResult(bool parsedOk, Dictionary<string, string> arguments)
    {
        ParsedOk = parsedOk;
        Arguments = arguments;
    }

    public bool ParsedOk { get; }
    public Dictionary<string, string> Arguments { get; }

    public static ArgumentParserResult Success(Dictionary<string, string> arguments)
    {
        return new ArgumentParserResult(true, arguments);
    }

    public static ArgumentParserResult Failure()
    {
        return new ArgumentParserResult(false, null);
    }
}