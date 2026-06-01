package io.jenkins.plugins.omniauth;

import hudson.Extension;
import hudson.init.InitMilestone;
import hudson.init.Initializer;
import hudson.security.AuthorizationStrategy;
import hudson.util.PluginServletFilter;
import jenkins.model.Jenkins;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Enumeration;

@Extension
public class OmniAuthPageDecorator {

    // Injected on job/folder Configure pages — grays out the per-item matrix section
    private static final String JOB_CONFIGURE_SCRIPT =
        "<script>(function(){" +
        "try{" +
        "if(!window.location.pathname.match(/\\/configure$/))return;" +
        "function run(){" +
        "var cb=document.querySelector('input[name=\"useProjectSecurity\"]');" +
        "if(!cb)return;" +
        "var c=cb.closest('.optionalBlock-container');" +
        "if(!c){c=cb.parentElement;var d=0;while(c){if(c.classList&&(c.classList.contains('jenkins-form-item')||c.classList.contains('optionalBlock-container')))break;c=c.parentElement;if(++d>10){c=null;break;}}}" +
        "if(!c)return;" +
        "var w=document.createElement('div');" +
        "w.style.cssText='position:relative;margin-bottom:4px;';" +
        "c.parentNode.insertBefore(w,c);" +
        "w.appendChild(c);" +
        "c.style.cssText='opacity:0.4;pointer-events:none;user-select:none;';" +
        "var b=document.createElement('div');" +
        "b.style.cssText='padding:10px 14px;background:#fff8e1;border:1px solid #ffcc02;border-radius:6px;margin-bottom:6px;font-size:13px;color:#795600;display:flex;align-items:center;gap:8px;';" +
        "b.innerHTML='<span style=\"font-size:16px\">⚠</span><span><strong>Managed by OmniAuth</strong> — Job-level permission matrix is disabled. Configure access via <strong>Manage Jenkins → OmniAuth → Access Management</strong>.</span>';" +
        "w.insertBefore(b,c);}" +
        "if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',run);}else{run();}" +
        "}catch(e){}" +
        "})();</script>";

    // Injected on /configureSecurity when OmniAuth is active — grays out the Authorization
    // matrix and adds the Emergency Override button + modal. Skipped during migration.
    private static final String SECURITY_CONFIGURE_SCRIPT =
        "<script>(function(){" +
        "try{" +
        "if(!window.location.pathname.match(/\\/configureSecurity(\\/)?$/))return;" +
        // Inject modal into body
        "var m=document.createElement('div');" +
        "m.id='omniauth-bg-modal';" +
        "m.style.cssText='display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);z-index:9999;align-items:center;justify-content:center;';" +
        "m.innerHTML='<div style=\"background:#fff;border-radius:8px;padding:24px;max-width:480px;width:90%;box-shadow:0 8px 32px rgba(0,0,0,0.2);\">" +
            "<h3 style=\"margin:0 0 16px;font-size:16px;color:#212529;\">Emergency Override</h3>" +
            "<div id=\\\"omniauth-bg-form\\\">" +
              "<p style=\\\"margin:0 0 16px;font-size:13px;color:#6c757d;\\\">Unlocks the Authorization table for 15 minutes. All actions are fully logged in OmniAuth Audit Log.</p>" +
              "<div style=\\\"margin-bottom:12px;\\\">" +
                "<label style=\\\"display:block;font-size:13px;font-weight:600;margin-bottom:4px;\\\">Reason <span style=\\\\\\\"color:#dc3545\\\\\\\">*</span></label>" +
                "<textarea id=\\\"omniauth-bg-reason\\\" placeholder=\\\"Why do you need emergency access?\\\" style=\\\"width:100%;height:72px;padding:8px;border:1px solid #ced4da;border-radius:4px;font-size:13px;resize:none;box-sizing:border-box;\\\"></textarea>" +
              "</div>" +
              "<div style=\\\"margin-bottom:16px;\\\">" +
                "<label style=\\\"display:block;font-size:13px;font-weight:600;margin-bottom:4px;\\\">TOTP Code <span style=\\\\\\\"color:#dc3545\\\\\\\">*</span></label>" +
                "<input id=\\\"omniauth-bg-totp\\\" type=\\\"text\\\" inputmode=\\\"numeric\\\" maxlength=\\\"6\\\" autocomplete=\\\"off\\\" placeholder=\\\"6-digit code\\\" style=\\\"width:100%;padding:8px;border:1px solid #ced4da;border-radius:4px;font-size:13px;box-sizing:border-box;letter-spacing:4px;\\\"/>" +
              "</div>" +
              "<div id=\\\"omniauth-bg-err\\\" style=\\\"display:none;padding:8px 12px;background:#f8d7da;border:1px solid #f5c6cb;border-radius:4px;font-size:12px;color:#721c24;margin-bottom:12px;\\\"></div>" +
              "<div style=\\\"display:flex;gap:8px;justify-content:flex-end;\\\">" +
                "<button type=\\\"button\\\" id=\\\"omniauth-bg-cancel\\\" style=\\\"padding:8px 16px;border:1px solid #ced4da;border-radius:4px;background:#fff;cursor:pointer;font-size:13px;\\\">Cancel</button>" +
                "<button type=\\\"button\\\" id=\\\"omniauth-bg-submit\\\" style=\\\"padding:8px 16px;border:none;border-radius:4px;background:#dc3545;color:#fff;cursor:pointer;font-size:13px;font-weight:600;\\\">Activate Override</button>" +
              "</div>" +
            "</div>" +
            "<div id=\\\"omniauth-bg-success\\\" style=\\\"display:none;text-align:center;padding:8px 0 4px;\\\">" +
              "<div style=\\\"font-size:40px;color:#27ae60;margin-bottom:10px;\\\">&#10003;</div>" +
              "<div style=\\\"font-size:15px;font-weight:600;color:#155724;margin-bottom:6px;\\\">Emergency Override Active</div>" +
              "<div style=\\\"font-size:13px;color:#6c757d;margin-bottom:4px;\\\">Authorization table is now unlocked for 15 minutes.</div>" +
              "<div style=\\\"font-size:13px;color:#6c757d;margin-bottom:14px;\\\">Reloading in <span id=\\\"omniauth-bg-secs\\\">5</span>s&hellip;</div>" +
              "<div style=\\\"height:4px;background:#e9ecef;border-radius:2px;margin-bottom:16px;overflow:hidden;\\\">" +
                "<div id=\\\"omniauth-bg-prog\\\" style=\\\"height:100%;width:100%;background:#27ae60;transition:width 5s linear;\\\"></div>" +
              "</div>" +
            "</div>" +
        "</div>';" +
        "document.body.appendChild(m);" +
        "document.getElementById('omniauth-bg-cancel').onclick=function(){m.style.display='none';};" +
        "document.getElementById('omniauth-bg-submit').onclick=function(){" +
          "var reason=document.getElementById('omniauth-bg-reason').value.trim();" +
          "var totp=document.getElementById('omniauth-bg-totp').value.trim();" +
          "var err=document.getElementById('omniauth-bg-err');" +
          "if(!reason){err.textContent='Reason is required.';err.style.display='block';return;}" +
          "if(!totp||totp.length!==6){err.textContent='Enter the 6-digit TOTP code.';err.style.display='block';return;}" +
          "err.style.display='none';" +
          "var btn=document.getElementById('omniauth-bg-submit');" +
          "btn.disabled=true;btn.textContent='Verifying...';" +
          "var base=window.location.pathname.split('/manage/')[0];" +
          "fetch(base+'/crumbIssuer/api/json')" +
          ".then(function(r){return r.json();})" +
          ".then(function(cd){" +
            "var xhr=new XMLHttpRequest();" +
            "xhr.open('POST',base+'/manage/omniauth-management/breakGlassActivate',true);" +
            "xhr.setRequestHeader('Content-Type','application/x-www-form-urlencoded');" +
            "xhr.setRequestHeader(cd.crumbRequestField,cd.crumb);" +
            "xhr.onload=function(){" +
              "btn.disabled=false;btn.textContent='Activate Override';" +
              "try{var r=JSON.parse(xhr.responseText);" +
                "if(r.success){" +
                  "document.getElementById('omniauth-bg-form').style.display='none';" +
                  "var s=document.getElementById('omniauth-bg-success');" +
                  "s.style.display='block';" +
                  "requestAnimationFrame(function(){requestAnimationFrame(function(){var p=document.getElementById('omniauth-bg-prog');if(p)p.style.width='0%';});});" +
                  "var secs=5;" +
                  "var iv=setInterval(function(){" +
                    "secs--;" +
                    "var el=document.getElementById('omniauth-bg-secs');if(el)el.textContent=secs;" +
                    "if(secs<=0){clearInterval(iv);window.onbeforeunload=null;window.location.reload();}" +
                  "},1000);" +
                "}" +
                "else{btn.disabled=false;btn.textContent='Activate Override';err.textContent=r.error||'Verification failed.';err.style.display='block';}" +
              "}catch(e){btn.disabled=false;btn.textContent='Activate Override';err.textContent='Server error ('+xhr.status+').';err.style.display='block';}" +
            "};" +
            "xhr.onerror=function(){btn.disabled=false;btn.textContent='Activate Override';err.textContent='Network error.';err.style.display='block';};" +
            "xhr.send('reason='+encodeURIComponent(reason)+'&totpCode='+encodeURIComponent(totp));" +
          "})" +
          ".catch(function(){btn.disabled=false;btn.textContent='Activate Override';err.textContent='Failed to fetch security token.';err.style.display='block';});" +
        "};" +
        "function run(){" +
        "if(document.getElementById('omniauth-migration-confirm'))return;" +
        "var ck=document.querySelector('input[type=\"checkbox\"][name*=\"hudson.model\"],input[type=\"checkbox\"][name*=\"jenkins.model\"],input[type=\"checkbox\"][name*=\"hudson.plugins\"]');" +
        "if(!ck)return;" +
        "var t=ck.closest('table');if(!t)return;" +
        "var c=t.parentElement;var depth=0;" +
        "while(c&&depth<6){" +
          "if(c.querySelector('button')||c.className==='repeated-container')break;" +
          "var p=c.parentElement;" +
          "if(!p||p.tagName==='FORM'||p.tagName==='BODY')break;" +
          "c=p;depth++;}" +
        "if(!c)return;" +
        "var w=document.createElement('div');" +
        "w.style.cssText='position:relative;margin-bottom:4px;';" +
        "c.parentNode.insertBefore(w,c);" +
        "w.appendChild(c);" +
        "c.style.cssText='opacity:0.4;pointer-events:none;user-select:none;';" +
        "var b=document.createElement('div');" +
        "b.style.cssText='padding:10px 14px;background:#fff8e1;border:1px solid #ffcc02;border-radius:6px;margin-bottom:6px;font-size:13px;color:#795600;display:flex;align-items:center;justify-content:space-between;gap:8px;';" +
        "b.innerHTML='<div style=\"display:flex;align-items:center;gap:8px;\"><span style=\"font-size:16px\">&#9888;</span><span><strong>Managed by OmniAuth</strong> &mdash; Authorization table is managed automatically. Configure access via <strong>Manage Jenkins &rarr; OmniAuth &rarr; Access Management</strong>.</span></div>" +
            "<button type=\"button\" id=\"omniauth-bg-open\" style=\"white-space:nowrap;padding:6px 12px;border:1px solid #dc3545;border-radius:4px;background:#fff;color:#dc3545;cursor:pointer;font-size:12px;font-weight:600;\">Emergency Override</button>';" +
        "w.insertBefore(b,c);" +
        "document.getElementById('omniauth-bg-open').onclick=function(){m.style.display='flex';};" +
        "}" +
        "if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',run);}else{run();}" +
        "}catch(e){}" +
        "})();</script>";

    // Injected on /configureSecurity when no TOTP device is enrolled — same banner, modal shows enroll prompt.
    private static final String SECURITY_CONFIGURE_SCRIPT_NOT_ENROLLED =
        "<script>(function(){" +
        "try{" +
        "if(!window.location.pathname.match(/\\/configureSecurity(\\/)?$/))return;" +
        "var m=document.createElement('div');" +
        "m.id='omniauth-bg-modal';" +
        "m.style.cssText='display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);z-index:9999;align-items:center;justify-content:center;';" +
        "m.innerHTML='<div style=\\\"background:#fff;border-radius:8px;padding:24px;max-width:480px;width:90%;box-shadow:0 8px 32px rgba(0,0,0,0.2);\\\">" +
            "<h3 style=\\\"margin:0 0 20px;font-size:16px;color:#212529;\\\">Emergency Override</h3>" +
            "<div style=\\\"text-align:center;padding:4px 0 16px;\\\">" +
              "<div style=\\\"font-size:36px;margin-bottom:12px;\\\">&#128274;</div>" +
              "<div style=\\\"font-size:14px;font-weight:600;color:#495057;margin-bottom:8px;\\\">No Authenticator Device Enrolled</div>" +
              "<div style=\\\"font-size:13px;color:#6c757d;margin-bottom:20px;\\\">Enroll a TOTP device on the Break Glass page before you can activate Emergency Override.</div>" +
              "<div style=\\\"display:flex;gap:8px;justify-content:center;\\\">" +
                "<button type=\\\"button\\\" id=\\\"omniauth-bg-cancel\\\" style=\\\"padding:8px 16px;border:1px solid #ced4da;border-radius:4px;background:#fff;cursor:pointer;font-size:13px;\\\">Cancel</button>" +
                "<a id=\\\"omniauth-bg-enroll-link\\\" href=\\\"#\\\" style=\\\"display:inline-flex;align-items:center;padding:8px 16px;border:none;border-radius:4px;background:#0d6efd;color:#fff;font-size:13px;font-weight:600;text-decoration:none;\\\">Set Up Break Glass &#8594;</a>" +
              "</div>" +
            "</div>" +
        "</div>';" +
        "document.body.appendChild(m);" +
        "document.getElementById('omniauth-bg-cancel').onclick=function(){m.style.display='none';};" +
        "var enrollEl=document.getElementById('omniauth-bg-enroll-link');" +
        "if(enrollEl){var base=window.location.pathname.split('/manage/')[0];enrollEl.href=base+'/manage/omniauth-management/breakGlass';}" +
        "function run(){" +
        "if(document.getElementById('omniauth-migration-confirm'))return;" +
        "var ck=document.querySelector('input[type=\"checkbox\"][name*=\"hudson.model\"],input[type=\"checkbox\"][name*=\"jenkins.model\"],input[type=\"checkbox\"][name*=\"hudson.plugins\"]');" +
        "if(!ck)return;" +
        "var t=ck.closest('table');if(!t)return;" +
        "var c=t.parentElement;var depth=0;" +
        "while(c&&depth<6){" +
          "if(c.querySelector('button')||c.className==='repeated-container')break;" +
          "var p=c.parentElement;" +
          "if(!p||p.tagName==='FORM'||p.tagName==='BODY')break;" +
          "c=p;depth++;}" +
        "if(!c)return;" +
        "var w=document.createElement('div');" +
        "w.style.cssText='position:relative;margin-bottom:4px;';" +
        "c.parentNode.insertBefore(w,c);" +
        "w.appendChild(c);" +
        "c.style.cssText='opacity:0.4;pointer-events:none;user-select:none;';" +
        "var b=document.createElement('div');" +
        "b.style.cssText='padding:10px 14px;background:#fff8e1;border:1px solid #ffcc02;border-radius:6px;margin-bottom:6px;font-size:13px;color:#795600;display:flex;align-items:center;justify-content:space-between;gap:8px;';" +
        "b.innerHTML='<div style=\"display:flex;align-items:center;gap:8px;\"><span style=\"font-size:16px\">&#9888;</span><span><strong>Managed by OmniAuth</strong> &mdash; Authorization table is managed automatically. Configure access via <strong>Manage Jenkins &rarr; OmniAuth &rarr; Access Management</strong>.</span></div>" +
            "<button type=\"button\" id=\"omniauth-bg-open\" style=\"white-space:nowrap;padding:6px 12px;border:1px solid #dc3545;border-radius:4px;background:#fff;color:#dc3545;cursor:pointer;font-size:12px;font-weight:600;\">Emergency Override</button>';" +
        "w.insertBefore(b,c);" +
        "document.getElementById('omniauth-bg-open').onclick=function(){m.style.display='flex';};" +
        "}" +
        "if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',run);}else{run();}" +
        "}catch(e){}" +
        "})();</script>";

    // Injected on all authenticated pages — JS exits early if not on a job page.
    private static final String JIT_BANNER_SCRIPT =
        "<script>(function(){" +
        "try{" +
        "function extractJobPath(p){" +
          "var m=p.match(/\\/job\\/(.+)/);" +
          "if(!m)return null;" +
          "var parts=m[1].split('/');" +
          "var out=[];" +
          "for(var i=0;i<parts.length;i++){" +
            "var s=parts[i];" +
            "if(!s||s==='job')continue;" +
            "if(/^\\d+$/.test(s)||['build','configure','workspace','changes','lastBuild','api','console','testReport','cobertura','robot'].indexOf(s)>=0)break;" +
            "out.push(s);" +
          "}" +
          "return out.length?out.join('/'):null;" +
        "}" +
        "var jobPath=extractJobPath(window.location.pathname);" +
        "if(!jobPath)return;" +
        "var base=window.location.href.split('/job/')[0];" +
        "function fetchStatus(){" +
          "fetch(base+'/omniauth-jit/status?job='+encodeURIComponent(jobPath),{credentials:'same-origin'})" +
          ".then(function(r){return r.json();})" +
          ".then(function(d){renderBanner(d);})" +
          ".catch(function(){});" +
        "}" +
        "function renderBanner(d){" +
          "if(!d||!d.hasJit)return;" +
          "removeBanner();" +
          "var banner=document.createElement('div');" +
          "banner.id='oau-jit-banner';" +
          "var color,icon,msg,actions;" +
          "if(d.status==='ACTIVE'){" +
            "var mins=Math.ceil(d.secondsRemaining/60);" +
            "color='#16a34a';icon='&#10003;';" +
            "msg='<strong>JIT Access active</strong> &mdash; approved by <strong>'+escHtml(d.approverId)+'</strong> &middot; expires in <strong id=\"oau-jit-countdown\">'+fmtTime(d.secondsRemaining)+'</strong>';" +
            "actions='<button type=\"button\" onclick=\"oauJitRevoke(\\''+escHtml(d.requestId)+'\\')\" style=\"padding:4px 12px;border:1px solid #16a34a;border-radius:4px;background:#fff;color:#16a34a;cursor:pointer;font-size:12px;font-weight:600;\">Revoke Early</button>';" +
            "startCountdown(d.secondsRemaining);" +
          "}else if(d.status==='PENDING'){" +
            "color='#d97706';icon='&#8987;';" +
            "msg='<strong>JIT request pending</strong> &mdash; waiting for approval &middot; requested '+escHtml(d.timeAgo);" +
            "actions='<button type=\"button\" onclick=\"oauJitCancel(\\''+escHtml(d.requestId)+'\\')\" style=\"padding:4px 12px;border:1px solid #d97706;border-radius:4px;background:#fff;color:#d97706;cursor:pointer;font-size:12px;font-weight:600;\">Cancel Request</button>';" +
          "}else{" +
            "color='#6366f1';icon='&#9889;';" +
            "var durOpts='';" +
            "for(var h=1;h<=d.maxDurationHours;h++){durOpts+='<option value=\"'+h+'\"'+(h===1?' selected':'')+'>'+h+' hour'+(h>1?'s':'')+'</option>';}" +
            "if(d.status==='DENIED'||d.status==='EXPIRED'||d.status==='TIMED_OUT'){" +
              "msg='<strong>JIT access required</strong> &mdash; previous request was <strong>'+d.status.toLowerCase()+'</strong>. Request again to build.';" +
            "}else{" +
              "msg='<strong>JIT access required</strong> &mdash; building this pipeline requires approval from '+escHtml(d.approverGroup||'an admin')+'.';" +
            "}" +
            "actions='<button type=\"button\" onclick=\"oauJitOpen()\" style=\"padding:4px 12px;border:none;border-radius:4px;background:#6366f1;color:#fff;cursor:pointer;font-size:12px;font-weight:600;\">&#9889; Request JIT Access</button>';" +
          "}" +
          "banner.style.cssText='margin:8px 16px;padding:10px 14px;border-radius:6px;background:#fff;border:1px solid '+color+';display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;';" +
          "banner.innerHTML='<div style=\"display:flex;align-items:center;gap:8px;font-size:13px;\"><span style=\"font-size:16px;color:'+color+';\">'+icon+'</span><span style=\"color:#333;\">'+msg+'</span></div><div style=\"display:flex;align-items:center;gap:8px;\">'+actions+'</div>';" +
          "var main=document.getElementById('main-panel')||document.querySelector('.jenkins-main-panel')||document.querySelector('[id*=\"main\"]');" +
          "if(main){main.insertBefore(banner,main.firstChild);}else{document.body.insertBefore(banner,document.body.firstChild);}" +
        "}" +
        "function removeBanner(){var b=document.getElementById('oau-jit-banner');if(b)b.remove();}" +
        "function fmtTime(s){var m=Math.floor(s/60);var ss=s%60;return m+'m '+(ss<10?'0':'')+ss+'s';}" +
        "function escHtml(s){if(!s)return'';return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;');}" +
        "var _cdInterval=null;" +
        "function startCountdown(secs){" +
          "if(_cdInterval)clearInterval(_cdInterval);" +
          "var rem=secs;" +
          "_cdInterval=setInterval(function(){" +
            "rem--;" +
            "var el=document.getElementById('oau-jit-countdown');" +
            "if(el)el.textContent=fmtTime(rem);" +
            "if(rem<=0){clearInterval(_cdInterval);fetchStatus();}" +
          "},1000);" +
        "}" +
        // Request modal
        "var _jitModal=null;" +
        "window.oauJitOpen=function(){" +
          "if(_jitModal){_jitModal.style.display='flex';return;}" +
          "var m=document.createElement('div');" +
          "_jitModal=m;" +
          "m.style.cssText='display:flex;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.45);z-index:9999;align-items:center;justify-content:center;';" +
          "var durOpts='';" +
          "fetch(base+'/omniauth-jit/status?job='+encodeURIComponent(jobPath),{credentials:'same-origin'})" +
          ".then(function(r){return r.json();})" +
          ".then(function(d){" +
            "for(var h=1;h<=d.maxDurationHours;h++){durOpts+='<option value=\"'+h+'\"'+(h===1?' selected':'')+'>'+h+' hour'+(h>1?'s':'')+'</option>';}" +
            "m.innerHTML='<div style=\"background:#fff;border-radius:8px;padding:24px;max-width:460px;width:90%;box-shadow:0 8px 32px rgba(0,0,0,0.18);\">'+" +
              "'<div style=\"font-size:15px;font-weight:700;margin-bottom:16px;\">&#9889; Request JIT Access</div>'+" +
              "'<div style=\"font-size:12px;color:#888;margin-bottom:16px;padding:8px 12px;background:#f5f5f5;border-radius:4px;\">'+" +
              "'<strong>Pipeline:</strong> '+escHtml(jobPath)+'<br/>'+" +
              "'<strong>Approver:</strong> '+escHtml(d.approverGroup||'Any admin')+'<br/>'+" +
              "'<strong>Auto-deny after:</strong> '+d.approvalTimeoutHours+' hour(s)'+" +
              "'</div>'+" +
              "'<div style=\"margin-bottom:12px;\"><label style=\"display:block;font-size:11px;font-weight:700;text-transform:uppercase;color:#888;margin-bottom:4px;\">Reason *</label>'+" +
              "'<textarea id=\"oau-jit-reason\" placeholder=\"Why do you need access? (e.g. Deploy v2.3.1, hotfix for JIRA-441)\" style=\"width:100%;height:72px;padding:8px;border:1px solid #ccc;border-radius:4px;font-size:13px;resize:none;box-sizing:border-box;\"></textarea></div>'+" +
              "'<div style=\"margin-bottom:16px;\"><label style=\"display:block;font-size:11px;font-weight:700;text-transform:uppercase;color:#888;margin-bottom:4px;\">Duration</label>'+" +
              "'<select id=\"oau-jit-dur\" style=\"width:100%;padding:8px;border:1px solid #ccc;border-radius:4px;font-size:13px;\">'+durOpts+'</select></div>'+" +
              "'<div id=\"oau-jit-err\" style=\"display:none;padding:8px 12px;background:#fee;border:1px solid #fca;border-radius:4px;font-size:12px;color:#c00;margin-bottom:12px;\"></div>'+" +
              "'<div style=\"display:flex;gap:8px;justify-content:flex-end;\">'+" +
              "'<button type=\"button\" onclick=\"oauJitClose()\" style=\"padding:8px 16px;border:1px solid #ccc;border-radius:4px;background:#fff;cursor:pointer;font-size:13px;\">Cancel</button>'+" +
              "'<button type=\"button\" id=\"oau-jit-submit\" onclick=\"oauJitSubmit()\" style=\"padding:8px 16px;border:none;border-radius:4px;background:#6366f1;color:#fff;cursor:pointer;font-size:13px;font-weight:600;\">Submit Request</button>'+" +
              "'</div></div>';" +
          "});" +
          "document.body.appendChild(m);" +
        "};" +
        "window.oauJitClose=function(){if(_jitModal)_jitModal.style.display='none';};" +
        "window.oauJitSubmit=function(){" +
          "var reason=document.getElementById('oau-jit-reason').value.trim();" +
          "var dur=document.getElementById('oau-jit-dur').value;" +
          "var err=document.getElementById('oau-jit-err');" +
          "if(!reason){err.textContent='Reason is required.';err.style.display='block';return;}" +
          "var btn=document.getElementById('oau-jit-submit');" +
          "btn.disabled=true;btn.textContent='Submitting...';" +
          "fetch(base+'/crumbIssuer/api/json',{credentials:'same-origin'})" +
          ".then(function(r){return r.json();})" +
          ".then(function(cd){" +
            "var body='job='+encodeURIComponent(jobPath)+'&reason='+encodeURIComponent(reason)+'&durationHours='+encodeURIComponent(dur);" +
            "var headers={'Content-Type':'application/x-www-form-urlencoded'};" +
            "headers[cd.crumbRequestField]=cd.crumb;" +
            "return fetch(base+'/omniauth-jit/request',{method:'POST',headers:headers,body:body,credentials:'same-origin'});" +
          "})" +
          ".then(function(r){return r.json();})" +
          ".then(function(data){" +
            "btn.disabled=false;btn.textContent='Submit Request';" +
            "if(data.ok){oauJitClose();fetchStatus();}else{err.textContent=data.error||'Request failed.';err.style.display='block';}" +
          "})" +
          ".catch(function(){btn.disabled=false;btn.textContent='Submit Request';err.textContent='Network error.';err.style.display='block';});" +
        "};" +
        "window.oauJitCancel=function(requestId){" +
          "if(!confirm('Cancel your pending JIT request?'))return;" +
          "fetch(base+'/crumbIssuer/api/json',{credentials:'same-origin'})" +
          ".then(function(r){return r.json();})" +
          ".then(function(cd){" +
            "var headers={'Content-Type':'application/x-www-form-urlencoded'};" +
            "headers[cd.crumbRequestField]=cd.crumb;" +
            "return fetch(base+'/omniauth-jit/cancel',{method:'POST',headers:headers,body:'requestId='+encodeURIComponent(requestId),credentials:'same-origin'});" +
          "})" +
          ".then(function(){fetchStatus();})" +
          ".catch(function(){});" +
        "};" +
        "window.oauJitRevoke=function(requestId){" +
          "if(!confirm('Revoke your active JIT access?'))return;" +
          "fetch(base+'/crumbIssuer/api/json',{credentials:'same-origin'})" +
          ".then(function(r){return r.json();})" +
          ".then(function(cd){" +
            "var headers={'Content-Type':'application/x-www-form-urlencoded'};" +
            "headers[cd.crumbRequestField]=cd.crumb;" +
            "return fetch(base+'/omniauth-jit/cancel',{method:'POST',headers:headers,body:'requestId='+encodeURIComponent(requestId),credentials:'same-origin'});" +
          "})" +
          ".then(function(){fetchStatus();})" +
          ".catch(function(){});" +
        "};" +
        "if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',fetchStatus);}else{fetchStatus();}" +
        "}catch(e){}" +
        "})();</script>";

    @Initializer(after = InitMilestone.EXTENSIONS_AUGMENTED)
    public static void registerFilter() throws Exception {
        PluginServletFilter.addFilter(new MatrixDisableFilter());
        PluginServletFilter.addFilter(new TotpReminderFilter());
        PluginServletFilter.addFilter(new JitBannerFilter());
    }

    private static class MatrixDisableFilter implements Filter {

        @Override public void init(FilterConfig config) {}
        @Override public void destroy() {}

        @Override
        public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
                throws IOException, ServletException {

            if (!(req instanceof HttpServletRequest)) {
                chain.doFilter(req, res);
                return;
            }

            HttpServletRequest httpReq = (HttpServletRequest) req;
            String path = httpReq.getRequestURI();

            String script = resolveScript(httpReq);
            if (script == null) {
                chain.doFilter(req, res);
                return;
            }

            HttpServletResponse httpRes = (HttpServletResponse) res;

            HttpServletRequest noGzipReq = new HttpServletRequestWrapper(httpReq) {
                @Override
                public String getHeader(String name) {
                    if ("Accept-Encoding".equalsIgnoreCase(name)) return null;
                    return super.getHeader(name);
                }
                @Override
                public Enumeration<String> getHeaders(String name) {
                    if ("Accept-Encoding".equalsIgnoreCase(name)) return Collections.emptyEnumeration();
                    return super.getHeaders(name);
                }
            };

            StreamCapture capture = new StreamCapture(httpRes);
            chain.doFilter(noGzipReq, capture);

            String contentType = capture.getContentType();
            byte[] body = capture.toByteArray();

            if (contentType != null && contentType.contains("text/html")) {
                String charset = StandardCharsets.UTF_8.name();
                if (contentType.contains("charset=")) {
                    charset = contentType.replaceAll(".*charset=([^;]+).*", "$1").trim();
                }
                String html = new String(body, charset);
                if (html.contains("</body>")) {
                    html = html.replace("</body>", script + "</body>");
                    body = html.getBytes(charset);
                }
            }

            httpRes.setContentLength(body.length);
            httpRes.getOutputStream().write(body);
        }

        private static String resolveScript(HttpServletRequest req) {
            String path = req.getRequestURI();
            if (path.endsWith("/configure") || path.endsWith("/configure/")) {
                return JOB_CONFIGURE_SCRIPT;
            }
            if (path.endsWith("/configureSecurity") || path.endsWith("/configureSecurity/")) {
                try {
                    AuthorizationStrategy s = Jenkins.get().getAuthorizationStrategy();
                    if (!(s instanceof OmniAuthAuthorizationStrategy)) return null;
                    // Check if break glass is currently active for this session
                    jakarta.servlet.http.HttpSession session = req.getSession(false);
                    if (session != null) {
                        Long expiry = (Long) session.getAttribute("omniauth.breakGlass.expiry");
                        if (expiry != null) {
                            if (System.currentTimeMillis() < expiry) {
                                return buildBreakGlassActiveScript(expiry);
                            }
                            // Expired — clean up
                            session.removeAttribute("omniauth.breakGlass.expiry");
                            session.removeAttribute("omniauth.breakGlass.user");
                            session.removeAttribute("omniauth.breakGlass.reason");
                        }
                    }
                    return isCurrentUserEnrolled() ? SECURITY_CONFIGURE_SCRIPT : SECURITY_CONFIGURE_SCRIPT_NOT_ENROLLED;
                } catch (Exception ignored) {}
            }
            return null;
        }

        private static boolean isCurrentUserEnrolled() {
            try {
                hudson.model.User current = hudson.model.User.current();
                if (current == null) return false;
                OmniAuthUserProperty prop = current.getProperty(OmniAuthUserProperty.class);
                return prop != null && prop.isBreakGlassTotpEnrolled();
            } catch (Exception ignored) {
                return false;
            }
        }

        private static String buildBreakGlassActiveScript(long expiryMs) {
            return "<script>(function(){" +
                "try{" +
                "if(!window.location.pathname.match(/\\/configureSecurity(\\/)?$/))return;" +
                "function run(){" +
                "var expiry=" + expiryMs + ";" +
                "var ck=document.querySelector('input[type=\"checkbox\"][name*=\"hudson.model\"],input[type=\"checkbox\"][name*=\"jenkins.model\"],input[type=\"checkbox\"][name*=\"hudson.plugins\"]');" +
                "if(!ck)return;" +
                "var t=ck.closest('table');if(!t)return;" +
                "var c=t.parentElement;var depth=0;" +
                "while(c&&depth<6){" +
                  "if(c.querySelector('button')||c.className==='repeated-container')break;" +
                  "var p=c.parentElement;" +
                  "if(!p||p.tagName==='FORM'||p.tagName==='BODY')break;" +
                  "c=p;depth++;}" +
                "if(!c)return;" +
                "var w=document.createElement('div');" +
                "w.style.cssText='position:relative;margin-bottom:4px;';" +
                "c.parentNode.insertBefore(w,c);" +
                "w.appendChild(c);" +
                "var b=document.createElement('div');" +
                "b.style.cssText='padding:10px 14px;background:#fff3cd;border:1px solid #ffc107;border-radius:6px;margin-bottom:6px;font-size:13px;color:#856404;display:flex;align-items:center;justify-content:space-between;gap:8px;';" +
                "b.innerHTML='<div style=\"display:flex;align-items:center;gap:8px;\"><span style=\"font-size:16px\">&#128275;</span><span><strong>Emergency Override Active</strong> &mdash; Authorization table is unlocked. Expires in <strong id=\"omniauth-timer\">--:--</strong>.</span></div>" +
                    "<button type=\"button\" id=\"omniauth-bg-end\" style=\"white-space:nowrap;padding:6px 12px;border:1px solid #856404;border-radius:4px;background:#fff;color:#856404;cursor:pointer;font-size:12px;font-weight:600;\">End Override Now</button>';" +
                "w.insertBefore(b,c);" +
                "function tick(){" +
                  "var rem=Math.max(0,expiry-Date.now());" +
                  "var mm=Math.floor(rem/60000);var ss=Math.floor((rem%60000)/1000);" +
                  "var el=document.getElementById('omniauth-timer');" +
                  "if(el)el.textContent=mm+':'+(ss<10?'0':'')+ss;" +
                  "if(rem<=0)window.location.reload();" +
                "}" +
                "tick();setInterval(tick,1000);" +
                "document.getElementById('omniauth-bg-end').onclick=function(){" +
                  "var base=window.location.pathname.split('/manage/')[0];" +
                  "fetch(base+'/crumbIssuer/api/json')" +
                  ".then(function(r){return r.json();})" +
                  ".then(function(cd){" +
                    "var xhr=new XMLHttpRequest();" +
                    "xhr.open('POST',base+'/manage/omniauth-management/breakGlassDeactivate',true);" +
                    "xhr.setRequestHeader('Content-Type','application/x-www-form-urlencoded');" +
                    "xhr.setRequestHeader(cd.crumbRequestField,cd.crumb);" +
                    "xhr.onload=function(){window.location.reload();};" +
                    "xhr.send('');" +
                  "});" +
                "};" +
                "}" +
                "if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',run);}else{run();}" +
                "}catch(e){}" +
                "})();</script>";
        }
    }

    private static class TotpReminderFilter implements Filter {

        private static final String SESSION_DONE   = "omniauth.totp.reminderDoneThisSession";
        private static final String SESSION_RETURN = "omniauth.totp.returnTo";

        @Override public void init(FilterConfig c) {}
        @Override public void destroy() {}

        @Override
        public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
                throws IOException, ServletException {

            if (!(req instanceof HttpServletRequest)) { chain.doFilter(req, res); return; }
            HttpServletRequest  httpReq = (HttpServletRequest)  req;
            HttpServletResponse httpRes = (HttpServletResponse) res;

            if (!"GET".equalsIgnoreCase(httpReq.getMethod()))                        { chain.doFilter(req, res); return; }
            if ("XMLHttpRequest".equals(httpReq.getHeader("X-Requested-With")))      { chain.doFilter(req, res); return; }
            if (isExcluded(httpReq.getRequestURI()))                                 { chain.doFilter(req, res); return; }

            try {
                Jenkins jenkins = Jenkins.getInstanceOrNull();
                if (jenkins == null)                                                  { chain.doFilter(req, res); return; }
                if (!(jenkins.getSecurityRealm() instanceof OmniAuthSecurityRealm))   { chain.doFilter(req, res); return; }
                if (!(jenkins.getAuthorizationStrategy() instanceof OmniAuthAuthorizationStrategy)) { chain.doFilter(req, res); return; }
                if (!jenkins.hasPermission(Jenkins.ADMINISTER))                      { chain.doFilter(req, res); return; }

                hudson.model.User current = hudson.model.User.current();
                if (current == null)                                                  { chain.doFilter(req, res); return; }

                OmniAuthUserProperty prop = current.getProperty(OmniAuthUserProperty.class);
                if (prop != null && prop.isBreakGlassTotpEnrolled())                 { chain.doFilter(req, res); return; }

                int  skips  = prop != null ? prop.getBreakGlassEnrollSkips() : 0;
                boolean forced = skips >= 3;

                // Always allow through if SESSION_DONE is set — covers the "last reminder dismiss"
                // case where doTotpReminderSkip sets SESSION_DONE just as skips reaches 3.
                // Next login the session is fresh, forced mode will show the wall.
                jakarta.servlet.http.HttpSession sess = httpReq.getSession(false);
                if (sess != null && Boolean.TRUE.equals(sess.getAttribute(SESSION_DONE))) { chain.doFilter(req, res); return; }

                if (!forced) {
                    // Mark shown for this session immediately to prevent redirect loops on sub-requests
                    httpReq.getSession(true).setAttribute(SESSION_DONE, Boolean.TRUE);
                }

                jakarta.servlet.http.HttpSession s = httpReq.getSession(true);
                if (s.getAttribute(SESSION_RETURN) == null) {
                    String uri = httpReq.getRequestURI();
                    String qs  = httpReq.getQueryString();
                    s.setAttribute(SESSION_RETURN, uri + (qs != null ? "?" + qs : ""));
                }

                httpRes.sendRedirect(httpReq.getContextPath() + "/manage/omniauth-management/totpReminder");

            } catch (Exception ignored) {
                chain.doFilter(req, res);
            }
        }

        private static boolean isExcluded(String path) {
            return path.contains("/totpReminder")   ||
                   path.contains("/breakGlass")     ||
                   path.contains("/crumbIssuer")    ||
                   path.contains("/api/")           ||
                   path.contains("/adjuncts/")      ||
                   path.contains("/static/")        ||
                   path.contains("/plugin/")        ||
                   path.contains("/images/")        ||
                   path.contains("/login")          ||
                   path.contains("/logout")         ||
                   path.contains("/securityRealm")  ||
                   path.endsWith(".js")             ||
                   path.endsWith(".css")            ||
                   path.endsWith(".ico")            ||
                   path.endsWith(".png")            ||
                   path.endsWith(".gif")            ||
                   path.endsWith(".woff2")          ||
                   path.endsWith(".ttf");
        }
    }

    private static class JitBannerFilter implements Filter {

        @Override public void init(FilterConfig c) {}
        @Override public void destroy() {}

        @Override
        public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
                throws IOException, ServletException {

            if (!(req instanceof HttpServletRequest)) { chain.doFilter(req, res); return; }
            HttpServletRequest  httpReq = (HttpServletRequest)  req;
            HttpServletResponse httpRes = (HttpServletResponse) res;

            if (!"GET".equalsIgnoreCase(httpReq.getMethod()))                        { chain.doFilter(req, res); return; }
            if ("XMLHttpRequest".equals(httpReq.getHeader("X-Requested-With")))      { chain.doFilter(req, res); return; }

            String path = httpReq.getRequestURI();
            if (!path.contains("/job/"))                                              { chain.doFilter(req, res); return; }
            if (isJitExcluded(path))                                                  { chain.doFilter(req, res); return; }

            try {
                Jenkins jenkins = Jenkins.getInstanceOrNull();
                if (jenkins == null)                                                  { chain.doFilter(req, res); return; }
                if (!(jenkins.getAuthorizationStrategy() instanceof OmniAuthAuthorizationStrategy)) { chain.doFilter(req, res); return; }
            } catch (Exception ignored) { chain.doFilter(req, res); return; }

            HttpServletRequest noGzipReq = new HttpServletRequestWrapper(httpReq) {
                @Override public String getHeader(String name) {
                    if ("Accept-Encoding".equalsIgnoreCase(name)) return null;
                    return super.getHeader(name);
                }
                @Override public java.util.Enumeration<String> getHeaders(String name) {
                    if ("Accept-Encoding".equalsIgnoreCase(name)) return java.util.Collections.emptyEnumeration();
                    return super.getHeaders(name);
                }
            };

            StreamCapture capture = new StreamCapture(httpRes);
            chain.doFilter(noGzipReq, capture);

            String contentType = capture.getContentType();
            byte[] body = capture.toByteArray();

            if (contentType != null && contentType.contains("text/html")) {
                String charset = "UTF-8";
                if (contentType.contains("charset=")) {
                    charset = contentType.replaceAll(".*charset=([^;]+).*", "$1").trim();
                }
                String html = new String(body, charset);
                if (html.contains("</body>")) {
                    html = html.replace("</body>", JIT_BANNER_SCRIPT + "</body>");
                    body = html.getBytes(charset);
                }
            }

            httpRes.setContentLength(body.length);
            httpRes.getOutputStream().write(body);
        }

        private static boolean isJitExcluded(String path) {
            return path.endsWith("/configure")     ||
                   path.endsWith("/configure/")    ||
                   path.contains("/configSubmit")  ||
                   path.contains("/api/")          ||
                   path.contains("/adjuncts/")     ||
                   path.contains("/static/")       ||
                   path.contains("/plugin/")       ||
                   path.endsWith(".js")            ||
                   path.endsWith(".css")           ||
                   path.endsWith(".ico")           ||
                   path.endsWith(".png");
        }
    }

    private static class StreamCapture extends HttpServletResponseWrapper {
        private final ByteArrayOutputStream bos = new ByteArrayOutputStream(64 * 1024);
        private final ServletOutputStream stream = new ServletOutputStream() {
            @Override public boolean isReady() { return true; }
            @Override public void setWriteListener(WriteListener wl) {}
            @Override public void write(int b) { bos.write(b); }
            @Override public void write(byte[] b, int off, int len) { bos.write(b, off, len); }
        };

        StreamCapture(HttpServletResponse response) {
            super(response);
        }

        @Override
        public ServletOutputStream getOutputStream() {
            return stream;
        }

        @Override
        public PrintWriter getWriter() {
            return new PrintWriter(bos);
        }

        public byte[] toByteArray() {
            return bos.toByteArray();
        }
    }
}
