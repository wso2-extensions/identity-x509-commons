package org.wso2.carbon.identity.x509Certificate.validation;

import java.io.IOException;
import java.security.cert.X509CRL;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.x509Certificate.validation.cache.CRLCacheEntry;

public class CacheEntryUpdate implements Runnable {
	
	private String crlURL;
	private CRLCacheEntry cacheEntry;

	private static final Log log = LogFactory.getLog(CacheEntryUpdate.class);
	@Override
	public void run() {
		boolean doUpdate = false;
		synchronized(cacheEntry) {  // Check if update is in progress. This is synchronized to make sure we have a singleton
			if (!cacheEntry.isUpdateInProgress()) {
				cacheEntry.setUpdateInProgress(true);
				log.info("Starting CRL cache update for " + crlURL + " at " + System.currentTimeMillis());
				doUpdate = true;
			} else {
				log.info("CRL cache update for " + crlURL + " already running. Not starting again");
			}
		}
		if (doUpdate) {
		X509CRL x509CRL = null;
			try {
				int retry = 0;
				while (x509CRL == null && retry++ < 100 ) {
					x509CRL = CertificateValidationUtil.downloadCRLFromWeb(crlURL, 1);  // Get the latest CRL
					if (x509CRL == null) {
						log.warn("Unable to update CRL for " + crlURL + " on attempt " + retry + ". Will try again in " + 5*retry + " seconds.");
						try {
							Thread.sleep(5000 * retry);
						} catch (InterruptedException e) {
							log.debug("Sleep interrupted");
						}
					}
				}
			} catch (IOException | CertificateValidationException e) {
				e.printStackTrace();
			}
			if (x509CRL == null) {  
				synchronized(cacheEntry) {  //Synchronize the setting of new CRL and release of the update in progress flag
					cacheEntry.setUpdateInProgress(false);
				}
				log.error("Failed to cache update for " + crlURL );
			} else {
				synchronized(cacheEntry) {  //Synchronize the setting of new CRL and release of the update in progress flag
					cacheEntry.setX509CRL(x509CRL);
					cacheEntry.setUpdateInProgress(false);
				}
				log.info("Finished cache update for " + crlURL + " at " + System.currentTimeMillis());
				
			}
		}
	}

	public CacheEntryUpdate(String crlURL, CRLCacheEntry cacheEntry) {
		super();
		this.crlURL = crlURL;
		this.cacheEntry = cacheEntry;
	}

}
