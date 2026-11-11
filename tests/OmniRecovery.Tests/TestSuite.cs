using System.Diagnostics;
using System.Text.Json;
namespace OmniRecovery.Tests;

public sealed class TestSuite
{
    private readonly List<(string Name,Func<Task> Action)> _tests=[];
    public string Root {get;}
    public TestSuite(string root){Root=Path.GetFullPath(root);Directory.CreateDirectory(Root);}
    public void Add(string name,Func<Task> action)=>_tests.Add((name,action));
    public void Add(string name,Action action)=>_tests.Add((name,()=>{action();return Task.CompletedTask;}));
    public void True(bool value,string message="Expected true"){if(!value)throw new Exception(message);}
    public void False(bool value,string message="Expected false")=>True(!value,message);
    public void Equal<T>(T expected,T actual,string? message=null){if(!EqualityComparer<T>.Default.Equals(expected,actual))throw new Exception(message??$"Expected {expected}; actual {actual}.");}
    public void Throws<T>(Action action) where T:Exception {try{action();}catch(T){return;}throw new Exception("Expected "+typeof(T).Name);}
    public async Task ThrowsAsync<T>(Func<Task> action) where T:Exception {try{await action();}catch(T){return;}throw new Exception("Expected "+typeof(T).Name);}
    public string NewDirectory(string name="fixture"){var p=Path.Combine(Root,name+"-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(p);return p;}
    public async Task<int> RunAsync(string reportPath)
    {
        var result=new List<object>();var failures=0;
        foreach(var test in _tests)
        {
            var watch=Stopwatch.StartNew();string? error=null;
            try{await test.Action().WaitAsync(TimeSpan.FromSeconds(90));}
            catch(Exception ex){failures++;error=ex.GetType().Name+": "+ex.Message;}
            Console.WriteLine((error is null?"PASS ":"FAIL ")+test.Name+(error is null?"":" — "+error));
            result.Add(new {name=test.Name,passed=error is null,duration_ms=watch.ElapsedMilliseconds,error});
        }
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(reportPath))!);
        await File.WriteAllTextAsync(reportPath,JsonSerializer.Serialize(new{observed_at=DateTimeOffset.UtcNow,total=_tests.Count,passed=_tests.Count-failures,failed=failures,scope="Synthetic fixtures and mocked HTTP; optional explicitly selected disposable MariaDB and PHP interoperability when enabled. No production database changes.",tests=result},new JsonSerializerOptions{WriteIndented=true}));
        Console.WriteLine($"RESULT {_tests.Count-failures}/{_tests.Count} passed");return failures==0?0:1;
    }
}
