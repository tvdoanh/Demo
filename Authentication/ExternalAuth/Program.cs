using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;
using Serilog.Events;
using Serilog.Sinks.SystemConsole.Themes;
using System;

namespace ExternalAuth
{
    public class Program
    {
        public static int Main(string[] args)
        {
            //CreateHostBuilder(args).Build().Run();
            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Debug()
                .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
                .MinimumLevel.Override("Microsoft.Hosting.Lifetime", LogEventLevel.Information)
                .MinimumLevel.Override("System", LogEventLevel.Warning)
                .MinimumLevel.Override("Microsoft.AspNetCore.Authentication", LogEventLevel.Information)
                .Enrich.FromLogContext()
                .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message:lj}{NewLine}{Exception}{NewLine}", theme: AnsiConsoleTheme.Code)
                .CreateLogger();

            var host = CreateHostBuilder(args).Build();

            using (var scope = host.Services.CreateScope())
            {

                var services = scope.ServiceProvider;

                try
                {
                    //Log.Information("Seeding database...");
                    //var dbInitializer = services.GetService<DataInitializer>();
                    //dbInitializer.Seed().Wait();
                    //Log.Information("Database seeding completed successfully");
                    host.Run();
                    return 0;
                }
                catch (Exception ex)
                {
                    Log.Fatal(ex, "Host terminated unexpectedly.");
                    return 1;
                }
                finally
                {
                    Log.CloseAndFlush();
                }
            }
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                    webBuilder.UseUrls("https://localhost:5001");
                });
    }
}
