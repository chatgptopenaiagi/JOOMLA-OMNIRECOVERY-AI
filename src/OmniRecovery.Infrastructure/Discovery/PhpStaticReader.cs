using System.Globalization;
using System.Text;

namespace OmniRecovery.Infrastructure.Discovery;

internal sealed record PhpToken(string Kind, string Text, bool Dynamic = false);
internal sealed record PhpValue(bool Resolved, string Text);
internal sealed class PhpDocument
{
    public Dictionary<string, PhpValue> Properties { get; } = new(StringComparer.Ordinal);
    public List<IReadOnlyList<PhpToken>> Includes { get; } = [];
    public bool Ambiguous { get; set; }
    public bool HasConfigurationClass { get; set; }
}

// A deliberately small PHP grammar, never an interpreter. Unknown syntax fails closed.
internal static class PhpStaticReader
{
    internal static IReadOnlyList<PhpToken> Tokenize(string text)
    {
        var tokens = new List<PhpToken>();
        for (var i = 0; i < text.Length;)
        {
            var c = text[i];
            if (char.IsWhiteSpace(c)) { i++; continue; }
            if (text.AsSpan(i).StartsWith("<?php", StringComparison.OrdinalIgnoreCase)) { i += 5; continue; }
            if (text.AsSpan(i).StartsWith("?>", StringComparison.Ordinal)) { i += 2; continue; }
            if (c == '#' || (c == '/' && i + 1 < text.Length && text[i + 1] == '/')) { while (i < text.Length && text[i] != '\n') i++; continue; }
            if (c == '/' && i + 1 < text.Length && text[i + 1] == '*')
            {
                var end = text.IndexOf("*/", i + 2, StringComparison.Ordinal);
                if (end < 0) throw new FormatException("Unterminated comment.");
                i = end + 2; continue;
            }
            if (c is '\'' or '"')
            {
                var quote = c; i++; var value = new StringBuilder(); var closed = false; var dynamic = false;
                while (i < text.Length)
                {
                    c = text[i++];
                    if (c == quote) { closed = true; break; }
                    if (c == '\\' && i < text.Length)
                    {
                        var next = text[i++];
                        if (quote == '\'') { if (next is '\\' or '\'') value.Append(next); else value.Append('\\').Append(next); }
                        else
                        {
                            switch (next)
                            {
                                case 'n': value.Append('\n'); break;
                                case 'r': value.Append('\r'); break;
                                case 't': value.Append('\t'); break;
                                case '\\': case '"': case '$': value.Append(next); break;
                                default: dynamic = true; value.Append('\\').Append(next); break;
                            }
                        }
                    }
                    else { if (quote == '"' && c == '$') dynamic = true; value.Append(c); }
                }
                if (!closed) throw new FormatException("Unterminated string.");
                tokens.Add(new("string", value.ToString(), dynamic)); continue;
            }
            if (char.IsLetter(c) || c == '_' || c == '$')
            {
                var start = i++; while (i < text.Length && (char.IsLetterOrDigit(text[i]) || text[i] == '_')) i++;
                tokens.Add(new(c == '$' ? "variable" : "identifier", text[start..i])); continue;
            }
            if (char.IsDigit(c))
            {
                var start = i++; while (i < text.Length && char.IsDigit(text[i])) i++;
                tokens.Add(new("number", text[start..i])); continue;
            }
            tokens.Add(new("symbol", c.ToString())); i++;
        }
        return tokens;
    }

    internal static PhpValue Evaluate(IReadOnlyList<PhpToken> tokens, string path, Func<string,string?> environment, bool allowEnvironment)
    {
        var position = 0;
        PhpValue Expression()
        {
            var value = Atom();
            while (position < tokens.Count && tokens[position].Text == ".")
            {
                position++; var right = Atom();
                value = new(value.Resolved && right.Resolved, value.Text + right.Text);
            }
            return value;
        }
        bool Take(string expected) { if (position < tokens.Count && tokens[position].Text.Equals(expected, StringComparison.OrdinalIgnoreCase)) { position++; return true; } return false; }
        PhpValue Atom()
        {
            if (position >= tokens.Count) return new(false, "");
            var t = tokens[position++];
            if (t.Kind == "string") return new(!t.Dynamic, t.Text);
            // Leading-zero PHP integers may be octal; do not silently reinterpret them as decimal.
            if (t.Kind == "number") return new(t.Text == "0" || !t.Text.StartsWith('0'), t.Text);
            if (t.Text == "(") { var value = Expression(); return Take(")") ? value : new(false, ""); }
            if (t.Text.Equals("__DIR__", StringComparison.OrdinalIgnoreCase)) return new(true, Path.GetDirectoryName(path)!);
            if (t.Text.Equals("__FILE__", StringComparison.OrdinalIgnoreCase)) return new(true, path);
            if (t.Text.Equals("dirname", StringComparison.OrdinalIgnoreCase) && Take("("))
            {
                var value = Expression();
                if (!Take(")") || !value.Resolved) return new(false, "");
                return new(true, Path.GetDirectoryName(value.Text) ?? "");
            }
            if (t.Text.Equals("getenv", StringComparison.OrdinalIgnoreCase) && allowEnvironment && Take("("))
            {
                // Only literal explicitly named variables are read. No environment enumeration.
                if (position >= tokens.Count || tokens[position].Kind != "string" || tokens[position].Dynamic) return new(false, "");
                var name = tokens[position++].Text;
                if (!Take(")") || name.Length is < 1 or > 256 || name.Any(ch => !(char.IsLetterOrDigit(ch) || ch == '_'))) return new(false, "");
                var value = environment(name); return new(value is not null, value ?? "");
            }
            return new(false, "");
        }
        var result = Expression();
        return position == tokens.Count && result.Text.Length <= 32768 ? result : new(false, "");
    }

    internal static PhpDocument Parse(string text, string path, Func<string,string?> environment)
    {
        var tokens = Tokenize(text); var result = new PhpDocument(); var p = 0;
        while (p < tokens.Count)
        {
            var token = tokens[p].Text;
            if (token == ";") { p++; continue; }
            if (token.Equals("class", StringComparison.OrdinalIgnoreCase) && p + 2 < tokens.Count && tokens[p + 1].Text.Equals("JConfig", StringComparison.OrdinalIgnoreCase))
            {
                if (result.HasConfigurationClass) result.Ambiguous = true;
                result.HasConfigurationClass = true; p += 2;
                if (p >= tokens.Count || tokens[p++].Text != "{") { result.Ambiguous = true; break; }
                while (p < tokens.Count && tokens[p].Text != "}")
                {
                    var start = p; var nested = 0;
                    while (p < tokens.Count)
                    {
                        if (tokens[p].Text == "{") nested++;
                        if (tokens[p].Text == "}") { if (nested == 0) break; nested--; }
                        if (tokens[p].Text == ";" && nested == 0) break;
                        p++;
                    }
                    var statement = tokens.Skip(start).Take(p - start).ToArray();
                    if (p < tokens.Count && tokens[p].Text == ";") p++;
                    if (statement.Length == 0) continue;
                    // JConfig data properties only. Methods/constructors, visibility changes and expressions fail closed.
                    var variable = Array.FindIndex(statement, t => t.Kind == "variable");
                    if (variable < 1 || statement[0].Text is not ("public" or "var") || statement.Take(variable).Any(t => t.Text is not ("public" or "var" or "string" or "int" or "bool")) || variable + 1 >= statement.Length || statement[variable + 1].Text != "=" || statement.Any(t => t.Text is "{" or "}"))
                    { result.Ambiguous = true; continue; }
                    var name = statement[variable].Text[1..];
                    var value = Evaluate(statement.Skip(variable + 2).ToArray(), path, environment, true);
                    if (!result.Properties.TryAdd(name, value)) { result.Properties[name] = new(false, ""); result.Ambiguous = true; }
                }
                if (p >= tokens.Count || tokens[p++].Text != "}") result.Ambiguous = true;
                continue;
            }
            if (token is "require" or "require_once" or "include" or "include_once")
            {
                p++; var start = p; while (p < tokens.Count && tokens[p].Text != ";") p++;
                if (p >= tokens.Count) { result.Ambiguous = true; break; }
                result.Includes.Add(tokens.Skip(start).Take(p - start).ToArray()); p++; continue;
            }
            // Joomla's conventional direct-access guard contains no credential mutation.
            if (token == "defined")
            {
                var start = p; while (p < tokens.Count && tokens[p].Text != ";") p++;
                var guard = tokens.Skip(start).Take(p - start).ToArray();
                var signature = string.Join(" ", guard.Select(t => t.Text));
                if (signature != "defined ( _JEXEC ) or die" && signature != "defined ( _JEXEC ) or die ( )") result.Ambiguous = true;
                if (p < tokens.Count) p++; continue;
            }
            result.Ambiguous = true; break;
        }
        return result;
    }
}
