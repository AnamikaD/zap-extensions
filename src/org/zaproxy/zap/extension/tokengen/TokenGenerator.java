/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0 
 *   
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */
package org.zaproxy.zap.extension.tokengen;

import java.net.SocketTimeoutException;
import java.util.concurrent.TimeUnit;

import javax.swing.SwingWorker;

import org.apache.log4j.Logger;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.params.HtmlParameterStats;

public class TokenGenerator extends SwingWorker<Void, Void> {
	
	private int numberTokens = 0;
	private HttpMessage httpMessage = null;
	private HttpSender httpSender = null;
	private HtmlParameterStats targetToken = null;
	private ExtensionTokenGen extension = null;
	private boolean stopGenerating = false;
	private boolean paused = false;
	private long requestDelayDuration;
	private TimeUnit requestDelayTimeUnit;
    private static Logger log = Logger.getLogger(TokenGenerator.class);

	private HttpSender getHttpSender() {
		if (httpSender == null) {
			//TODO Replace with HttpSender.TOKEN_GENERATOR_INITIATOR when available.
			httpSender = new HttpSender(Model.getSingleton().getOptionsParam().getConnectionParam(), true, 12);
		}
		return httpSender;
	}

	@Override
	protected Void doInBackground() throws Exception {
		for (int i=0; i < numberTokens; i++) {
			while (paused && ! this.stopGenerating) {
				try {
					Thread.sleep (500);
				} catch (InterruptedException e) {
					// Ignore
				}
			}
			if (this.stopGenerating) {
				break;
			}

			HttpMessage msg = this.httpMessage.cloneRequest();

			requestDelayTimeUnit.sleep(requestDelayDuration);

			try {
				msg.getRequestHeader().setHeader(HttpHeader.COOKIE, null);
				this.getHttpSender().sendAndReceive(msg, true);
			} catch (SocketTimeoutException ste) {
				log.debug("A timout occurred while sending a request to generate a token. Reducing sent count, initiating supplemental request.");
				i--;
			} catch (Exception e) {
				log.error(e.getMessage(), e);
			}
			this.extension.addTokenResult(msg, targetToken);
		}
		this.extension.generatorStopped(this);

		return null;
	}

	public void setNumberTokens(int numberTokens) {
		this.numberTokens = numberTokens;
	}

	public void setHttpMessage(HttpMessage httpMessage) {
		this.httpMessage = httpMessage;
	}

	protected HttpMessage getHttpMessage() {
		return httpMessage;
	}

	public void setTargetToken(HtmlParameterStats targetToken) {
		this.targetToken = targetToken;
	}

	public void stopGenerating() {
		this.stopGenerating = true;
	}

	public void setExtension(ExtensionTokenGen extension) {
		this.extension = extension;
	}

	public boolean isPaused() {
		return paused;
	}

	public void setPaused(boolean paused) {
		this.paused = paused;
	}

	public void setRequestDelay(long duration, TimeUnit timeUnit) {
		if (timeUnit == null) {
			throw new IllegalArgumentException("The parameter timeUnit must not be null.");
		}
		this.requestDelayDuration = duration;
		this.requestDelayTimeUnit = timeUnit;
	}
}
