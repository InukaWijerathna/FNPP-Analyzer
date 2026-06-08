namespace FNPPAnalyzer.Tests;

public class TruncatePathTests
{
    [Fact]
    public void ShortPath_IsReturnedUnchanged()
    {
        Assert.Equal(@"C:\Temp\a.exe", Program.TruncatePath(@"C:\Temp\a.exe", 50));
    }

    [Fact]
    public void LongPath_IsElidedInTheMiddle_AndKeepsFileName()
    {
        string path = @"C:\Users\HP\AppData\Local\Temp\algo_workspace\kohonen_som_topology.cpp";

        string result = Program.TruncatePath(path, 40);

        Assert.True(result.Length <= 40);
        Assert.EndsWith("kohonen_som_topology.cpp", result);
        Assert.Contains('…', result);
    }

    [Fact]
    public void FileNameAlone_LongerThanLimit_IsTakenFromTheEnd()
    {
        string path = @"C:\a_file_name_that_is_far_too_long_to_fit.exe";

        string result = Program.TruncatePath(path, 10);

        Assert.Equal(10, result.Length);
        Assert.Equal("to_fit.exe", result);
    }

    [Fact]
    public void NoRoomForEllipsis_ReturnsFileNameOnly()
    {
        string path = @"C:\Temp\name.exe";

        string result = Program.TruncatePath(path, "name.exe".Length);

        Assert.Equal("name.exe", result);
    }
}
