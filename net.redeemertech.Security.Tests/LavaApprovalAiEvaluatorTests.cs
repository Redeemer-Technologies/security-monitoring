using System;
using System.Reflection;

using Microsoft.VisualStudio.TestTools.UnitTesting;

using net.redeemertech.Security;

namespace net.redeemertech.Security.Tests
{
    [TestClass]
    public class LavaApprovalAiEvaluatorTests
    {
        [TestMethod]
        public void BuildUserPromptAddsLavaWebhookSecurityRequirements()
        {
            var prompt = InvokeBuildUserPrompt( "{{ Request.QueryString.id }}", true );

            StringAssert.Contains( prompt, "does not enforce authentication or authorization" );
            StringAssert.Contains( prompt, "Rate it high risk if that gating is absent" );
            StringAssert.Contains( prompt, "entity data by ID" );
            StringAssert.Contains( prompt, "ID swapping" );
            StringAssert.Contains( prompt, "SQL injection, JavaScript injection, XSS" );
        }

        [TestMethod]
        public void BuildUserPromptOmitsLavaWebhookRequirementsForOtherSources()
        {
            var prompt = InvokeBuildUserPrompt( "{{ Person.NickName }}", false );

            Assert.IsFalse( prompt.Contains( "Lava Webhook template" ) );
            Assert.IsFalse( prompt.Contains( "ID swapping" ) );
            StringAssert.Contains( prompt, "{{ Person.NickName }}" );
        }

        private static string InvokeBuildUserPrompt( string content, bool isLavaWebhook )
        {
            var evaluator = new LavaApprovalAiEvaluator();
            var method = typeof( LavaApprovalAiEvaluator ).GetMethod( "BuildUserPrompt", BindingFlags.Instance | BindingFlags.NonPublic );
            if ( method == null )
            {
                throw new InvalidOperationException( "BuildUserPrompt method was not found." );
            }

            return ( string )method.Invoke( evaluator, new object[] { content, isLavaWebhook } );
        }
    }
}
