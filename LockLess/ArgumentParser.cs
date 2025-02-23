﻿using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace LockLess;

public static class ArgumentParser
{
    public static ArgumentParserResult Parse(IEnumerable<string> args)
    {
        Dictionary<string, string> arguments = new Dictionary<string, string>();
        try
        {
            foreach (string argument in args)
            {
                int idx = argument.IndexOf(':');
                if (idx > 0)
                {
                    arguments[argument.Substring(0, idx)] = argument.Substring(idx + 1);
                }
                else
                {
                    arguments[argument] = string.Empty;
                }
            }

            return ArgumentParserResult.Success(arguments);
        }
        catch (Exception ex)
        {
            Debug.WriteLine(ex.Message);
            return ArgumentParserResult.Failure();
        }
    }
}