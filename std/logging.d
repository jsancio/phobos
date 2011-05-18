// Written in the D programming language.

/++
Implements application level _logging mechanism.

This module defines a set of functions useful for many common _logging tasks.  The module must be initialized (ideally in single threaded mode) by calling $(D initializeLogging). Messages of different severity level are logged by calling the template function $(D log). Verbose messages can be logged by calling the template function $(D vlog).

Examples:
---
import std.logging;

int main(string[] args)
{
   initializeLogging(SharedLogger.getCreator(args[0]));

   log!info.format("You passed %s argument(s)", args.length - 1);
   log!info(args.length > 1).write("Arguments: ", args[1 .. $]);

   log!info.write("This is an info message.");
   log!warning.write("This is a warning message.");
   log!error.write("This is an error message!");
   log!fatal.write("This is a fatal message");

   vlog(0).write("Verbosity 0 message");
   vlog(1).write("Verbosity 1 message");
   vlog(2).write("Verbosity 2 message");

   foreach (i; 0 .. 10)
   {
      log!info(every(9)).write("Every nine");
 
      auto logger = log!info;
      if(logger.willLog)
      {
         auto message = "Cool message";
         // perform some complex operation
         // ...
         logger.write(message);
      }

      vlog(2, first).write("Verbose message only on the first iterations");
   }

   log!fatal.write("This is a fatal message!!!");
}
---

Note:
Compile time disabling of severity levels can be done by defining the LOGGING_FATAL_DISABLED, LOGGING_ERROR_DISABLED, LOGGING_WARNING_DISABLED or LOGGING_INFO_DISABLED version. Disabiliting a higher serveirty level will disable all the lower severity level. E.g. LOGGING_WARNING_DISABLED will disable warning and info serverity levels at compile time and enable the fatal and error serverity level.

Verbose messages are logged at the info severity level so using LOGGING_INFO_DISABLED will also disable versbose messages.

Macros:
D = $(B$(U $0))
+/
module std.logging;

import core.atomic : cas;
import core.sync.mutex : Mutex;
import std.stdio : File, write, writefln;
import std.string : newline;
import std.conv : text, to;
import std.datetime: Clock, DateTime;
import std.exception : enforce;
import std.concurrency : spawn,
                         Tid,
                         send,
                         receive,
                         OwnerTerminated,
                         thisTid,
                         receiveOnly;
import std.traits : EnumMembers;
import std.array : appender, array, replicate;
import std.format : formattedWrite;
import std.algorithm : endsWith, startsWith, splitter;

version(unittest)
{
   import std.file : remove;
   import core.exception : AssertError;
}

/++
Defines the severity levels supported by the logging library.

Logging messages of severity level fatal will also cause the program to halt. The dfatal severity will log at a fatal severity in debug mode and at a error severity in release mode.
+/
enum fatal = 0;
enum error = 1; /// ditto
enum warning = 2; /// ditto
enum info = 3; /// ditto
debug alias fatal dfatal; /// ditto
else alias error dfatal; /// ditto

private enum levelMax = 4;

immutable string[] severityNames = [ "FATAL", "ERROR", "WARNING", "INFO" ];

// Set the compile time level for compile time filtering
version(LOGGING_FATAL_DISABLED)
{
   private enum compiledLevel = -1;
}
else version(LOGGING_ERROR_DISABLED)
{
   private enum compiledLevel = fatal;
}
else version(LOGGING_WARNING_DISABLED)
{
   private enum compiledLevel = error;
}
else version(LOGGING_INFO_DISABLED)
{
   private enum compiledLevel = warning;
}
else
{
   private enum compiledLevel = info;
}

/++
Initializes the logging infrastructure.

This function must be called once before calling any of the logging functions.

Params:
   logCreator = Delegate which creates the Logger used by the module.
   logConfig = Module configuration object. 

See_Also:
   LogConfig
+/
// XXX fix the API so that most user don't need to know about ActorLogger
void initializeLogging(shared(Logger) delegate() logCreator,
                       LogConfig logConfig = LogConfig())
{
   _internal.init(logCreator, logConfig);
}

/++
Logs a message.

Returns a structure for logging messages at the specified level.
Example:
---
   log!error.write("Log an ", severityNames[error], " message!");
   log!error.format("Also logs an %s message!", severityNames[error]);
---

You can also performed conditional logging.
Example:
---
   void coolFunction(Object object)
   {
      log!fatal(object is null).write("I don't like null objects!");
      // ...
   }

   foreach(i; 0 .. 10)
   {
      log!info(first).write("Only log this the first time in the loop");
   }
---

The returned object can be reused.
Example:
---
   auto logger = log!warning;
   with(logger)
   {
      if(willLog)
      {
         auto message = "A complex message...";
         // Continue constructing 'message'...

         write(message);
      }
   }
---

+/
auto log(int level)
        (lazy bool now = true,
         string file = __FILE__,
         int line = __LINE__)
{
   static assert(level >= fatal && level < levelMax);

   static if(level <= compiledLevel)
   {
      return _internal.getLog(file, line, level, now);
   }
   else
   {
      return NoopLogged.init;
   }
}

/++
Logs a verbose message.

Returns a structure for logging messages at the specified verbose level.
Example:
---
   vlog(0).write("Log a verbose ", 0, " message!");
   vlog(2).format("Also logs a verbose %s message!", 0);
---

You can also performed conditional verbose logging.
Example:
---
   foreach(i; 0 .. 10)
   {
      vlog(3, first).write("Only log this the first time in the loop");
   }
---

The returned object can be reused.
Example:
---
   auto logger = vlog(1);
   with(logger)
   {
      if(willLog)
      {
         auto message = "A complex message...";
         // Continue constructing 'message'...

         write(message);
      }
   }
---
+/
auto vlog(uint level,
          lazy bool now = true,
          string file = __FILE__,
          int line = __LINE__)
{
   static if(info <= compiledLevel)
   {
      return _internal.getVlog(file, line, level, now);
   }
   else
   {
      return NoopLogged.init;
   }
}

/++
Returned by the log and vlog functions.
+/
struct Logged
{
/++
Returns true when write and format will lead to a message being logged.
+/
   @property bool willLog() const { return _logger !is null; }
   
/++
Records each argument in one log line or record.

Example:
---
   auto pi = 3.14159265;

   auto logger = log!info;
   logger.write("The value of pi is ", pi);

   // The same as above...
   log!info.write("The value of pi is ", pi);
---
+/
   void write(T...)(T args)
   {
      // XXX change this to use formattedWrite's new format string
      if(_logger)
      {
        _message.message = text(args);
        _logger.log(_message);
      }
   }

/++
Records formatted message in one log line or record.

Example:
---
   auto goldenRatio = 1.61803399;

   auto logger = log!info;
   logger.format("The number %s is the golden ratio", goldenRatio);

   // The same as above...
   log!info.format("The number %s is the golden ratio", goldenRatio);
---
+/
   void format(T...)(string fmt, T args)
   {
      if(_logger)
      {
         auto writer = appender!string();
         writer.reserve(fmt.length);
         formattedWrite(writer, fmt, args);

         _message.message = writer.data;
         _logger.log(_message);
      }
   }

   private shared(InternalLogging) * _logger;
   private Logger.LogMessage _message;
}

struct NoopLogged
{
   @property bool willLog() const { return false; }

   void write(T...)(T args) {}
   void format(T...)(string fmt, T args) {}
}

/++
Configuration struct for the module.

This object must be used to configure the logging module at initialization.  All the properties are optional and can be use to configure the framework's behavior.
+/
struct LogConfig
{
/++
Level to use for _logging.

The logging framework will only log messages with a severity greater than or equal to the value of this property.
+/
   @property void level(uint level)
   {
      enforce(level < levelMax);
      _level = level;
   }

/++
Verbose logging configuration.

Messages logged by using the template function $(D vlog) or $(D vlogf) will be filtered by comparing against each VLogConfig until a match is found. If no match is found the verbose message will not get logged.

See_Also:
   VLogConfig
+/
   @property void vLogConfigs(VLogConfig[] vLogConfigs)
   {
      _vLogConfigs = vLogConfigs;
   }

/++
Function pointer for handling log message with a severity of fatal.

This function will be called by the thread trying to log a fatal message by using $(D log) or $(D logf). The function $(I fatalHandler) should not return; otherwise the framework will assert(false).
+/
   @property void fatalHandler(void function() fatalHandler)
   {
      _fatalHandler = fatalHandler;
   }

   private string _name;
   private int _level = error;
   private VLogConfig[] _vLogConfigs;
   private void function() _fatalHandler;
}

unittest
{
   // Test level filtering
   class LevelFilter : Logger
   {
      shared void log(const ref LogMessage msg)
      {
         called = true;
         level = msg.level;
         message = msg.message;
      }

      shared void flush()
      {
         flushCalled = true;
      }

      shared void clear()
      {
         message = string.init;
         level = -1;
         called = false;
         flushCalled = false;
      }

      string message;
      int level;
      bool called;
      bool flushCalled;
   }

   LogConfig logConfig;
   logConfig.level = warning;
   logConfig.vLogConfigs = VLogConfig.create("*logging.d=2");

   auto logger = cast(shared) new LevelFilter();
   InternalLogging logging;

   logging.init({ return cast(shared(Logger)) logger; },
                logConfig);

   auto loggedMessage = "logged message";

   // Test logging and level filtering
   logging.getLog("package/logging.d", 11, info, true).write(loggedMessage);
   assert(!logger.called);

   logger.clear();
   logging.getLog("package/logging.d", 11, warning, true).write(loggedMessage);
   assert(logger.called);
   assert(logger.level == warning &&
          logger.message == loggedMessage);

   logger.clear();
   logging.getLog("package/logging.d", 11, error, true).write(loggedMessage);
   assert(logger.called);
   assert(logger.level == error &&
          logger.message == loggedMessage);

   logger.clear();
   logging.getLog("package/logging.d", 11, error, true).write(loggedMessage);
   assert(logger.called);
   assert(logger.level == error &&
          logger.message == loggedMessage);

   // XXX this is ugly. Fix this test. look into using assertThrown
   logger.clear();
   try
   {
      logging.getLog("package/logging.d", 11, fatal, true).write(loggedMessage);
      assert(false);
   }
   catch (AssertError e) {}
   assert(logger.called);
   assert(logger.level == fatal &&
          logger.message == loggedMessage);
   assert(logger.flushCalled);

   logger.clear();
   logging.getLog("package/logging.d", 11, warning, true).write(loggedMessage);
   assert(logger.called);
   assert(logger.level == warning &&
          logger.message == loggedMessage);

   // Test vlogging and module filtering
   logger.clear();
   logging.getVlog("package/logging.d", 11, 2, true).write(loggedMessage);
   assert(logger.called);
   assert(logger.level == info &&
          logger.message == loggedMessage);

   logger.clear();
   logging.getVlog("package/logging.d", 11, 3, true).write(loggedMessage);
   assert(!logger.called);

   logger.clear();
   logging.getVlog("not_this_file", 22, 0, true).write(loggedMessage);
   assert(!logger.called); 

   logger.clear();
   logging.getVlog("package/logging.d", 11, 2, true).write(loggedMessage);
   assert(logger.called);
   assert(logger.level == info &&
	       logger.message == loggedMessage);
}

// TODO: fix core.Thread so that ThreadAddr is exposed
private shared struct InternalLogging
{
   private static __gshared auto noopLogged = Logged.init;

   void init(shared(Logger) delegate() logCreator,
             LogConfig logConfig)
   { 
      enforce(cas(&_initialized, false, true));

      _vLogConfigs = logConfig._vLogConfigs.idup;
      _logger = logCreator();
      _level = logConfig._level;
      _fatalHandler =  logConfig._fatalHandler ? 
                       logConfig._fatalHandler :
                       function {};
   }

   Logged getVlog(string file, int line, uint level, lazy bool now)
   in
   {
      assert(_initialized);
   }
   body
   {
      if(logMatches(file, level, _vLogConfigs) && now)
      {
         return Logged(&this, Logger.LogMessage(file,
                                                line,
                                                info,
                                                0, // XXX thread id
                                                "",
                                                true,
                                                level));
      }

      return noopLogged;
   }

   Logged getLog(string file, int line, int level, lazy bool now)
   in
   {
      assert(_initialized);
   }
   body
   {
      if(level <= _level && now) 
      {
         return Logged(&this, Logger.LogMessage(file,
                                                line,
                                                level,
                                                0, // XXX thread id
                                                "",
                                                false,
                                                0));
      }
      
      return noopLogged;
   }

   void log(const ref Logger.LogMessage message)
   {
      scope(exit)
      {
         if(message.level == fatal)
         {
            /+
             + The other of the scope(exit) is important. We want
             + _fatalHandler to run before the assert.
             +/
            scope(exit) assert(false);
            scope(exit) _fatalHandler();
            _logger.flush();
         }
      }

      _logger.log(message);
   }

   private bool _initialized;
   private Logger _logger;
   private int _level;
   private immutable(VLogConfig)[] _vLogConfigs;
   private __gshared void function() _fatalHandler;
}

unittest
{
   // Test equals
   VLogConfig[] configs = [ VLogConfig("package/module",
                                       VLogConfig.Matching.equals,
                                       1) ];
   assert(logMatches("package/module", 1, configs));
   assert(logMatches("package/module.d", 1, configs));
   assert(logMatches("package/module", 0, configs));

   assert(!logMatches("module", 1, configs));
   assert(!logMatches("package/module", 2, configs));

   // Test startsWith
   configs[0]._pattern = "package";
   configs[0]._matching = VLogConfig.Matching.startsWith,
   configs[0]._level = 1;
   assert(logMatches("package/module", 1, configs));
   assert(logMatches("package/module.d", 1, configs));
   assert(logMatches("package/module", 0, configs));
   assert(logMatches("package/another.d", 1, configs));

   assert(!logMatches("module", 1, configs));
   assert(!logMatches("another/package/module", 1, configs));
   assert(!logMatches("package/module.d", 2, configs));

   // Test endsWith
   configs[0]._pattern = "module";
   configs[0]._matching = VLogConfig.Matching.endsWith,
   configs[0]._level = 1;
   assert(logMatches("package/module", 1, configs));
   assert(logMatches("package/module.d", 1, configs));
   assert(logMatches("package/module", 0, configs));
   assert(logMatches("module", 1, configs));

   assert(!logMatches("another", 1, configs));
   assert(!logMatches("package/module", 2, configs));
}

private bool logMatches(string file,
                        uint level,
                        const VLogConfig[] configs)
{
   foreach(config; configs)
   {
      if(config.match(file, level)) return true;
   }

   return false;
} 

unittest
{
   auto result = VLogConfig.create("module=1,*another=3,even*=2");
   assert(result.length == 3);
   assert(result[0]._pattern == "module");
   assert(result[0]._matching == VLogConfig.Matching.equals);
   assert(result[0]._level == 1);

   assert(result[1]._pattern == "another");
   assert(result[1]._matching == VLogConfig.Matching.endsWith);
   assert(result[1]._level == 3);

   assert(result[2]._pattern == "even");
   assert(result[2]._matching == VLogConfig.Matching.startsWith);
   assert(result[2]._level == 2);

   try
   {
      VLogConfig.create("module=2,");
      assert(false);
   }
   catch (Exception e) {}

   try
   {
      VLogConfig.create("module=a");
      assert(false);
   }
   catch (Exception e) {}

   try
   {
      VLogConfig.create("module=2,another=");
      assert(false);
   }
   catch (Exception e) {}

   try
   {
      VLogConfig.create("module=2,ano*ther=3");
      assert(false);
   }
   catch (Exception e) {}

   try
   {
      VLogConfig.create("module=2,*another*=3");
      assert(false);
   }
   catch (Exception e) {}
}

/++
Structure for configuring verbose logging.

This structure is used to control verbose logging on a per module basis. A verbose message with level $(I x) will get logged at severity level info if there is a VLogConfig entry that matches to the source file and the verbose level of that entry is greater than or equal to $(I x).
+/
struct VLogConfig
{
   private enum Matching
   {
      startsWith,
      endsWith,
      equals
   } 

/++
Creates an array of $(D VLogConfig) based on a configuration string.

The format of the configuration string is as follow "$(B [pattern])=$(B [level]),...", where $(B [pattern]) may contain any character allowed in a file name and $(B [level]) must be convertible to an positive integer (greater than or equal to zero). If $(B [pattern]) contains a '*' then it must be at the start or the end. If $(B [pattern]) ends with a '*' then it will match any source file name that starts with the rest of $(B [pattern]). If $(B [pattern]) starts with a '*' then it will match any source file name that ends with a the rest of $(B [pattern]).

For every $(B [pattern])=$(B [level]) in the configuration string a $(D VLogConfig) will be created and included in the returned array.

Example:
---
auto configs = VLogConfig.create("special/module=2,great/*=3,*/test=1");
---

The code above will return a verbose logging configuration that will:
$(DL
$(DD 1. Log verbose 2 and lower messages from special/module{,.d})
$(DD 2. Log verbose 3 and lower messages from package great)
$(DD 3. Log verbose 1 and lower messages from any file that ends with test{,.d})
)
+/
   static VLogConfig[] create(string config)
   {
      VLogConfig[] result;
      foreach(entry; splitter(config, ","))
      {
         enforce(entry != "");
         auto entryParts = array(splitter(entry, "="));
         enforce(entryParts.length == 2);

         auto mod = array(splitter(entryParts[0], "*"));
         enforce(mod.length == 1 || mod.length == 2);
         
         if(mod.length == 1 && mod[0] != "")
         {
            VLogConfig logConfig = VLogConfig(mod[0],
                                              Matching.equals,
                                              to!uint(entryParts[1]));
            result ~= logConfig;
         }
         else if(mod[0] != "" && mod[1] == "")
         {
            VLogConfig logConfig = VLogConfig(mod[0],
                                              Matching.startsWith,
                                              to!uint(entryParts[1]));
            result ~= logConfig;
         }
         else if(mod[0] == "" && mod[1] != "")
         {
            VLogConfig logConfig = VLogConfig(mod[1],
                                              Matching.endsWith,
                                              to!uint(entryParts[1]));
            result ~= logConfig;
         }
         else
         {
            enforce(false);
         }
      }

      return result;
   }

   private bool match(string file, uint level) const
   { 
      auto match = false;
      // XXX file but against startWith/endsWith for not allowing const
      auto pattern = cast(string) _pattern;

      final switch(_matching)
      {
         case VLogConfig.Matching.startsWith:
            match = startsWith(file, pattern) &&
                         level <= _level; 
            break;
         case VLogConfig.Matching.endsWith:
            match = (endsWith(file, pattern) ||
                     endsWith(file, pattern ~ ".d")) && 
                    level <= _level; 
            break;
         case VLogConfig.Matching.equals:
            match = (file == pattern ||
                     file == pattern ~ ".d") &&
                    level <= _level; 
            break;
      }

      return match;
   }

   private this(string pattern, Matching matching, uint level)
   {
      _pattern = pattern;
      _matching = matching;
      _level = level;
   }

   private string _pattern;
   private Matching _matching;
   private uint _level;
}

/++
Extension point for the module.
+/
interface Logger
{
   public static struct LogMessage
   {
      string file;
      int line;
      int level;
      int threadId;
      string message;

      bool isVerbose;
      uint verbose;

      string logLine() const
      {
         // XXX add verbose level
         // XXX add time stamp
         auto writer = appender!string();
         formattedWrite(writer,
                        "%s:%d:%s:%d %s%s",
                        file,
                        line,
                        severityNames[level],
                        threadId,
                        message,
                        newline);

         return writer.data;
      }
   }

/++
Logs a message.

The method is called by the logging module whenever it decides that a message should be logged. It is recommend that the implementation of this method doesn't perform any filtering based on level since at this point all configured filters were applied.

The method is allow to return immediately without persisting the message.
+/
   shared void log(const ref LogMessage message);

/++
Flushes pending log operations.

The method is called by the logging framework whenever it requires that the persistence of all previous log messages. For example the method is called when the client logs a fatal message.

The method must not return until all pending log operations complete.
+/
   shared void flush();
}

/++
+/
// XXX Allow storing file in a diff dir
// XXX Allow the configuration of the log file name
class SharedLogger : Logger
{
   private this(string name)
   {
      BufferedWriter!FileWriter[] bufferedWriters(FileWriter[] writers)
      {
         auto buffers = new BufferedWriter!FileWriter[writers.length];
         foreach(i, ref writer; writers)
         {
            buffers[i] = BufferedWriter!FileWriter(writer);
         }

         return buffers;
      }

      _writers = bufferedWriters(createFileWriters(name));
      _mutex = new Mutex;
   }

   static shared(Logger) delegate() getCreator(string name)
   {
      shared(Logger) creator()
      { 
         static Logger logger;
         logger = logger ? logger : new SharedLogger(name);
         return cast(shared(Logger)) logger;
      }

      return &creator;
   }

   shared void log(const ref LogMessage message)
   {
      synchronized(_mutex)
      {
         foreach(i, ref writer; _writers)
         {
            if(i >= message.level) writer.put(message.logLine());
         }
      }
   }

   shared void flush()
   {
      synchronized(_mutex)
      {
         foreach(ref writer; _writers)
         {
            writer.flush();
         }
      }
   }

   private Mutex _mutex;
   __gshared BufferedWriter!FileWriter[] _writers;
}

unittest
{
   void removeTestLogs(FileWriter[] writers)
   {
      foreach(ref writer; writers)
      {
         auto name = writer._file.name;
         writer._file.close();
         remove(name);
      }
   }

   auto msgs = ["fatal message",
                "error message",
                "warning message",
                "info message"];

   auto fileWriters = createFileWriters("logging_level_unittest");
   auto logger = new MultiWriter!FileWriter(fileWriters);
   scope(exit) removeTestLogs(fileWriters);

   foreach(level; 0 .. levelMax)
   {
      auto msg = Logger.LogMessage("",
                                   0,
                                   level,
                                   0,
                                   msgs[level],
                                   false,
                                   0);

      logger.log(msg);
   }

   /+
    + Check the content of the files: for every file for severity level 'x'
    + there should be a message from a severity level <= 'x'. 
    +/
   foreach(fileLevel; 0 .. levelMax)
   {
      fileWriters[fileLevel]._file.flush();
      auto file = File(fileWriters[fileLevel]._file.name, "r");
      for(auto level = 0; level <= fileLevel; ++level)
      {
         auto line = file.readln();
         assert(endsWith(line, msgs[level] ~ newline));
      }
   }
}

private class MultiWriter(LogWriter)
{
   this(LogWriter[] writers)
   {
      assert(writers.length == compiledLevel + 1);
      _writers = writers;
   }


   void log(const ref Logger.LogMessage message)
   {
      for(int aLevel = message.level; aLevel <= compiledLevel; ++aLevel)
      {
         _writers[aLevel].put(message.logLine());
      }
   }

   void flush()
   {
      foreach(ref writer; _writers)
      {
         writer.flush();
      }
   }


   private LogWriter[] _writers;
}


private FileWriter[] createFileWriters(string name)
{
   auto time = cast(DateTime) Clock.currTime();

   // Create file for every level
   auto writers = new FileWriter[compiledLevel + 1];
   foreach(aLevel; 0 .. compiledLevel + 1)
   {
      auto filename = text(name,
                           ".log.",
                           severityNames[aLevel],
                           ".",
                           time.toISOString());
      writers[aLevel] = FileWriter(File(filename, "w"));
   }

   return writers;
}

unittest
{
   auto writer = appender!(char[])();
   size_t size = 1024;
   auto buffer = BufferedWriter!(typeof(writer))(writer, size);

   // check that internal writer is not called
   auto smallMsg = "1234567890";
   buffer.put(smallMsg);
   assert(writer.data == "");

   // check that internal writer is called when buffer overflows
   auto bigMsg = replicate("a", size - 5);
   buffer.put(bigMsg);
   assert(startsWith(writer.data, smallMsg[0 .. 3]));

   // check that everything is written when flush is called
   buffer.flush();
   assert(writer.data[0 .. smallMsg.length] == smallMsg);
   assert(writer.data[smallMsg.length .. $] == bigMsg);

   // check that messages bigger than the buffer are also written
   writer.clear();
   auto reallyBigMsg = replicate("b", size + 5);
   buffer.put(reallyBigMsg);
   buffer.flush();
   assert(writer.data == reallyBigMsg);
}

// XXX check Writer
private struct BufferedWriter(Writer)
{
   this(Writer writer, size_t bufferSize = 1024 * 4)
   {
      _writer = writer;
      _remainder = _buffer = new char[bufferSize];
   }

   // XXX implement this(this)

   void put(string msg)
   {
      if(_buffer is _remainder &&  _remainder.length <= msg.length)
      {
         // the message will never fit just write it
         _writer.put(msg);
      }
      else if(_remainder.length > msg.length)
      {
         // there is enough space so buffer the message
         _remainder[0 .. msg.length] = msg;
         _remainder = _remainder[msg.length .. $];
      }
      else
      {
         // not enought space: flush and log
         flush();
         put(msg);
      }
   }

   void flush()
   {
      _writer.put(_buffer[0 .. $ - _remainder.length]);
      _remainder = _buffer;
   }

   private Writer _writer;
   private char[] _buffer;
   private char[] _remainder;
}

// XXX check Writer
private struct FileWriter
{
   this(File file)
   {
      _file = file;
   }

   void put(const char[] msg)
   {
      _file.write(msg);
   }

   void flush() {}

   private File _file;
}

private shared InternalLogging _internal;

static if(false)
{
/++
Implements an actor based logging backend.

Log messages are sent to a logging thread which is responsible for persisting log messages. Messages of a given severity will be written in the log file of that severity and in the log files of lower severity. The file names of the log files created will follow the following pattern "$(B [name]).log.$(B [level]).$(B [time])". The string $(B [name]) is the parameter $(I name) passed to $(D getCreator). The string $(B [time]) is the time when the logger was created. The string $(B [level]) is the severity of the log file. A file for severity level 'x' will contain all log messages of greater or equal severity.
+/
class ActorLogger : Logger
{
   private struct Flush {}

   private this(string name)
   {
      _actor = spawn(&loggerMain, name);
   }

/++
Returns a delegate for creating an ActorLogger.

The method will always return a different delegate but a given delegate will always return the same $(D ActorLogger).

Params:
   name = Name to use when creating log files
+/
   static shared(Logger) delegate() getCreator(string name)
   {
      shared(Logger) creator()
      { 
         static Logger logger;
         logger = logger ? logger : new ActorLogger(name);
         return cast(shared(Logger)) logger;
      }

      return &creator;
   }

   shared void log(const ref LogMessage message)
   {
      LogMessage msg = message;
      send(cast(Tid) _actor, msg);
   }

   shared void flush()
   {
      send(cast(Tid) _actor, thisTid, Flush());
      receiveOnly!Flush();
   }

   private Tid _actor;
}

private void loggerMain(string name)
{
   BufferedWriter!FileWriter[] bufferedWriters(FileWriter[] writers)
   {
      auto buffers = new BufferedWriter!FileWriter[writers.length];
      foreach(i, ref writer; writers)
      {
         buffers[i] = BufferedWriter!FileWriter(writer);
      }

      return buffers;
   }

   auto logger = new MultiWriter!(BufferedWriter!FileWriter)
                                 (bufferedWriters(createFileWriters(name)));
   auto done = false;

   void log(Logger.LogMessage message)
   {
      logger.log(message);
   }

   void flush(Tid sender, ActorLogger.Flush flush)
   {
      logger.flush();
      send(sender, flush);
   }

   void terminate(OwnerTerminated e)
   {
      done = true;
   }

   while(!done)
   {
      receive(&log, &flush, &terminate);
   }
}
}

// XXX unittest
/++
+/
bool every(string file = __FILE__, int line = __LINE__)(uint times)
{
   static uint counter;
   if(++counter > times) counter -= times;

   return counter == 1;
}

// XXX unittest
/++
+/
bool first(string file = __FILE__, int line = __LINE__)(uint times = 1)
{
   static uint counter;
   if(++counter > times + 1) counter = times + 1;

   return counter <= times;
}
