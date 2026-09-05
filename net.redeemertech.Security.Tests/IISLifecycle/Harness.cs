using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Web;
using System.Web.Script.Serialization;

// Runs the production module handlers in IIS Express, with only database-backed
// cache initialization and background side effects replaced by an in-memory probe.
public sealed class LifecycleHarness : IHttpModule
{
    private static readonly Assembly Plugin = Assembly.Load("net.redeemertech.Security");
    private static readonly Type ModuleType = Plugin.GetType("net.redeemertech.Security.IISAlertBlockHttpModule", true);
    private static readonly object Gate = new object();
    private static bool initialized;
    private static int evaluationClock;
    public void Dispose() { }
    public void Init(HttpApplication application)
    {
        lock (Gate)
        {
            if (!initialized)
            {
                InitializeConfiguration();
                initialized = true;
            }
        }
        var module = System.Runtime.Serialization.FormatterServices.GetUninitializedObject(ModuleType);
        Bind(application, module, "BeginRequest", "Application_BeginRequest");
        Bind(application, module, "PostAuthenticateRequest", "Application_PostAuthenticateRequest");
        Bind(application, module, "EndRequest", "Application_EndRequest");
        Bind(application, module, "PreSendRequestContent", "Application_PreSendRequestContent");
        application.EndRequest += (sender, args) => Record(((HttpApplication)sender).Context, "EndRequest");
        application.PreSendRequestContent += (sender, args) => Record(((HttpApplication)sender).Context, "PreSendRequestContent");
        application.RequestCompleted += (sender, args) => Record(((HttpApplication)sender).Context, "RequestCompleted");
    }
    private static void Bind(HttpApplication app, object module, string eventName, string methodName)
    {
        var method = ModuleType.GetMethod(methodName, BindingFlags.Instance | BindingFlags.NonPublic);
        app.GetType().GetEvent(eventName).AddEventHandler(app, Delegate.CreateDelegate(typeof(EventHandler), module, method));
    }
    private static void InitializeConfiguration()
    {
        var condition = new net.redeemertech.Security.Model.IISRequestRuleCondition
        {
            Field = "ResponseBytes",
            Operator = net.redeemertech.Security.Model.IISRequestRuleOperator.GreaterThanOrEqual,
            Value = "0"
        };
        var rule = new net.redeemertech.Security.IISRealtimeRule(-100, "IIS lifecycle probe",
            net.redeemertech.Security.Model.IISRequestRuleStage.EndRequest,
            net.redeemertech.Security.Model.IISRequestRuleConditionLogic.All,
            null, null, 1, false, 403, null, false, 60, false,
            new[] { condition }, new[] { new net.redeemertech.Security.Model.IISRequestRuleConditionMatcher(condition) });
        net.redeemertech.Security.IISAlertRuleCache.PublishConfiguration(
            new net.redeemertech.Security.IISAlertRuleConfiguration(new[] { rule }));
        // Advancing beyond the cooldown makes duplicate stage execution visible.
        net.redeemertech.Security.IISAlertRequestRuleProcessor.CurrentDateTime = () =>
            new DateTime(2026, 1, 1).AddMinutes(System.Threading.Interlocked.Increment(ref evaluationClock) * 2);
        net.redeemertech.Security.IISAlertRealtimeActionProcessor.QueueOverride = captured =>
        {
            Record(HttpContext.Current, "RuleMatched");
            return true;
        };
        Plugin.GetType("net.redeemertech.Security.IISAlertBlockedIpCache", true)
            .GetField("_isLoaded", BindingFlags.Static | BindingFlags.NonPublic).SetValue(null, true);
    }
    private static void Set(object target, string name, object value) { target.GetType().GetProperty(name).SetValue(target, value); }
    private static void Record(HttpContext context, string eventName)
    {
        if (context == null || context.Request.Path.EndsWith("results.ashx")) return;
        var snapshot = context.Items["__RedeemertechIISRequestRuleSnapshot__"];
        var result = new Dictionary<string, object> { { "event", eventName }, { "mode", context.Request.QueryString["mode"] } };
        if (snapshot != null)
        {
            result["bytes"] = snapshot.GetType().GetProperty("ResponseBytes").GetValue(snapshot);
            result["available"] = snapshot.GetType().GetProperty("ResponseBytesAvailable").GetValue(snapshot);
        }
        result["processed"] = context.Items["__RedeemertechIISEndRequestRuleProcessed__"];
        lock (Gate) File.AppendAllText(context.Server.MapPath("~/events.jsonl"), new JavaScriptSerializer().Serialize(result) + Environment.NewLine);
    }
}

public sealed class ProbeHandler : IHttpHandler
{
    public bool IsReusable { get { return false; } }
    public void ProcessRequest(HttpContext context)
    {
        context.Response.ContentType = "application/octet-stream";
        var mode = context.Request.QueryString["mode"];
        context.Response.BufferOutput = mode != "streaming";
        if (mode == "emptyflush") context.Response.Flush();
        if (mode == "empty") return;
        context.Response.BinaryWrite(new byte[17]);
        if (mode == "flush" || mode == "streaming") context.Response.Flush();
        if (mode == "early")
        {
            context.ApplicationInstance.CompleteRequest();
            return;
        }
        if (mode == "end") { context.Response.End(); return; }
        context.Response.BinaryWrite(new byte[29]);
        if (mode == "streaming") context.Response.Flush();
    }
}



