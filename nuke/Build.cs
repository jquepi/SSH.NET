using System;
using System.Linq;
using Nuke.Common;
using Nuke.Common.CI;
using Nuke.Common.Execution;
using Nuke.Common.Git;
using Nuke.Common.IO;
using Nuke.Common.ProjectModel;
using Nuke.Common.Tooling;
using Nuke.Common.Tools.DotNet;
using Nuke.Common.Utilities.Collections;
using Nuke.OctoVersion;
using OctoVersion.Core;
using OctoVersion.Core.OutputFormatting.TeamCity;
using static Nuke.Common.EnvironmentInfo;
using static Nuke.Common.IO.FileSystemTasks;
using static Nuke.Common.IO.PathConstruction;
using static Nuke.Common.Tools.DotNet.DotNetTasks;

[CheckBuildProjectConfigurations]
[ShutdownDotNetAfterServerBuild]
class Build : NukeBuild
{
    /// Support plugins are available for:
    ///   - JetBrains ReSharper        https://nuke.build/resharper
    ///   - JetBrains Rider            https://nuke.build/rider
    ///   - Microsoft VisualStudio     https://nuke.build/visualstudio
    ///   - Microsoft VSCode           https://nuke.build/vscode

        public static int Main () => Execute<Build>(x => x.Pack);

    [Parameter("Configuration to build - Default is 'Debug' (local) or 'Release' (server)")]
    readonly Configuration Configuration = IsLocalBuild ? Configuration.Debug : Configuration.Release;

    [Solution] readonly Solution Solution;
    [NukeOctoVersion] readonly OctoVersionInfo OctoVersionInfo;

    OctoVersionInfo NewVersion;

    AbsolutePath SourceDirectory => RootDirectory / "src";
    AbsolutePath TempDir => RootDirectory / "build" / "temp";
    AbsolutePath ArtifactsDirectory => RootDirectory / "artifacts";
    AbsolutePath LocalPackagesDirectory => RootDirectory / ".." / "LocalPackages";
    Target Clean => _ => _
        .Before(Restore)
        .Executes(() =>
        {
            SourceDirectory.GlobDirectories("**/bin", "**/obj", "**/TestResults").ForEach(DeleteDirectory);
            EnsureCleanDirectory(TempDir);
            EnsureCleanDirectory(ArtifactsDirectory);
        });

    Target CalculateVersion => _ => _
        .DependsOn(Clean)
        .Executes(() =>
        {
            // generate new version and overwrite teamcity build number
            var octoVersion = new OctoVersionInfo(2020, 0, 1, $"{OctoVersionInfo.PreReleaseTag}{OctoVersionInfo.Patch}", OctoVersionInfo.BuildMetadata);
            var teamCityOutputFormatter = new TeamCityOutputFormatter();
            teamCityOutputFormatter.Write(octoVersion);
            NewVersion = octoVersion;
        });

    Target Restore => _ => _
        .DependsOn(Clean)
        .Executes(() =>
        {
            DotNetRestore(s => s
                .SetProjectFile(Solution));
        });
    Target Compile => _ => _
        .DependsOn(CalculateVersion)
        .DependsOn(Restore)
        .DependsOn(Clean)
        .Executes(() =>
        {
            DotNetBuild(s => s
                .SetProjectFile(Solution)
                .SetConfiguration(Configuration)
                .SetVersion(NewVersion.FullSemVer)
                .SetInformationalVersion(NewVersion.BuildMetadataWithPlus)
                .EnableNoRestore()
            );
        });

    Target Pack => _ => _
        .DependsOn(CalculateVersion)
        .DependsOn(Compile)
        .Executes(() =>
        {
            DotNetPack(s => s
                .SetProject(Solution)
                .SetConfiguration(Configuration)
                .SetOutputDirectory(ArtifactsDirectory)
                .SetRunCodeAnalysis(false)
                .SetIncludeSymbols(false)
                .SetNoBuild(false) // Don't change this flag we need it because of https://github.com/dotnet/msbuild/issues/5566
                .AddProperty("Version", NewVersion.FullSemVer )
            );
        });

    Target CopyToLocalPackages => _ => _
        .OnlyWhenStatic(() => IsLocalBuild)
        .TriggeredBy(Pack)
        .Executes(() =>
        {
            EnsureExistingDirectory(LocalPackagesDirectory);
            GlobFiles(ArtifactsDirectory, $"*.{NewVersion.FullSemVer}.nupkg").ForEach(x => CopyFileToDirectory(x, LocalPackagesDirectory, FileExistsPolicy.Overwrite));
        });

}
