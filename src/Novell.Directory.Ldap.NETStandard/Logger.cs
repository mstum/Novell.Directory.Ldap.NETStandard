using System;
using Microsoft.Extensions.Logging;

namespace Novell.Directory.Ldap
{
    public static class Logger
    {
        private static ILoggerFactory _loggerFactory;

        static Logger()
        {
            Factory = new LoggerFactory().AddDebug();
        }

        public static ILoggerFactory Factory
        {
            get => _loggerFactory;
            set
            {
                _loggerFactory = value;
                Init();
            }
        }

        public static ILogger Log { get; private set; }

        public static void LogWarning(this ILogger logger, string message, Exception ex)
        {
            logger.LogWarning(message + " - {0}", ex.ToString());
        }

        private static void Init()
        {
            Log = _loggerFactory.CreateLogger("Ldap");
        }

        public class NullLogger : ILogger
        {
            public static readonly ILogger Instance = new NullLogger();

            private NullLogger()
            {
            }

            public IDisposable BeginScope<TState>(TState state)
                => NullDisposable.Instance;

            public bool IsEnabled(LogLevel logLevel) => false;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
            {
            }

            private sealed class NullDisposable : IDisposable
            {
                public static readonly IDisposable Instance = new NullDisposable();

                public void Dispose() { }
            }
        }
    }
}