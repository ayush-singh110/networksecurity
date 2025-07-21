import pandas as pd
import numpy as np
from networksecurity.utils.feature_extraction import WebsiteFeatureExtractor
from networksecurity.utils.main_utils.utils import load_object
import warnings
import urllib3

# Disable SSL warnings and other noisy warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")

class FalsePositiveAnalyzer:
    def __init__(self):
        """Initialize with loaded model and preprocessor"""
        try:
            self.preprocessor = load_object("final_model/preprocessor.pkl")
            self.model = load_object("final_model/model.pkl")
            print("Successfully loaded model and preprocessor")
        except Exception as e:
            raise RuntimeError(f"Failed to load model files: {str(e)}")

    def analyze_urls(self, test_urls):
        """Analyze multiple URLs and return results DataFrame"""
        results = []
        for url in test_urls:
            result = self._analyze_single_url(url)
            results.append(result)
        return pd.DataFrame(results)

    def _analyze_single_url(self, url):
        """Analyze a single URL and return prediction results"""
        REQUIRED_FEATURES = [
            "having_IP_Address", "URL_Length", "Shortining_Service",
            "having_At_Symbol", "double_slash_redirecting", "Prefix_Suffix",
            "having_Sub_Domain", "SSLfinal_State", "Domain_registeration_length",
            "Favicon", "port", "HTTPS_token", "Request_URL", "URL_of_Anchor",
            "Links_in_tags", "SFH", "Submitting_to_email", "Abnormal_URL",
            "Redirect", "on_mouseover", "RightClick", "popUpWidnow", "Iframe",
            "age_of_domain", "DNSRecord", "web_traffic", "Page_Rank",
            "Google_Index", "Links_pointing_to_page", "Statistical_report"
        ]

        try:
            print(f"Analyzing URL: {url}")
            extractor = WebsiteFeatureExtractor(url)
            features = extractor.get_features_for_model()
            
            # Debug: Print extracted features
            print(f"Extracted {len(features)} features")
            
            # Validate features exist
            missing = [f for f in REQUIRED_FEATURES if f not in features]
            if missing:
                print(f"Warning: Missing features: {missing}")
                # Fill missing features with default values
                for feature in missing:
                    features[feature] = -1
            
            # Create DataFrame with enforced column order
            feature_values = [features.get(f, -1) for f in REQUIRED_FEATURES]
            df = pd.DataFrame([feature_values], columns=REQUIRED_FEATURES)
            
            print(f"Feature DataFrame shape: {df.shape}")
            print(f"Feature values: {df.iloc[0].to_dict()}")
            
            # Transform features using preprocessor
            processed = self.preprocessor.transform(df)
            print(f"Processed features shape: {processed.shape}")
            
            # Make predictions
            proba = self.model.predict_proba(processed)[0]
            prediction = self.model.predict(processed)[0]
            
            print(f"Prediction: {prediction}, Probabilities: {proba}")
            
            return {
                'url': url,
                'prediction': int(prediction),
                'probability_phishing': float(proba[1]),
                'probability_legitimate': float(proba[0]),
                'error': None,
                'features_extracted': len(features),
                'missing_features': len(missing)
            }
            
        except Exception as e:
            print(f"ERROR analyzing {url}: {str(e)}")
            import traceback
            print(f"Full traceback: {traceback.format_exc()}")
            return {
                'url': url,
                'prediction': None,
                'probability_phishing': None,
                'probability_legitimate': None,
                'error': str(e),
                'features_extracted': 0,
                'missing_features': len(REQUIRED_FEATURES)
            }

    def debug_feature_extraction(self, url):
        """Debug feature extraction process for a single URL"""
        print(f"\n=== DEBUG: Feature extraction for {url} ===")
        
        try:
            extractor = WebsiteFeatureExtractor(url)
            
            # Check if URL is accessible
            if extractor.response:
                print(f"✓ URL accessible, status: {extractor.response.status_code}")
                print(f"✓ Response size: {len(extractor.response.content)} bytes")
            else:
                print("✗ URL not accessible")
            
            # Check if HTML parsing worked
            if extractor.soup:
                print(f"✓ HTML parsed successfully")
            else:
                print("✗ HTML parsing failed")
            
            # Extract features one by one for debugging
            feature_methods = {
                'having_IP_Address': extractor.check_ip_address,
                'URL_Length': extractor.get_url_length,
                'Shortining_Service': extractor.check_shortening_service,
                'having_At_Symbol': extractor.check_at_symbol,
                'double_slash_redirecting': extractor.check_double_slash,
                'Prefix_Suffix': extractor.check_prefix_suffix,
                'having_Sub_Domain': extractor.count_subdomains,
                'SSLfinal_State': extractor.check_ssl_state,
                'Domain_registeration_length': extractor.get_domain_reg_length,
                'Favicon': extractor.check_favicon,
                'port': extractor.check_port,
                'HTTPS_token': extractor.check_https_token,
                'Request_URL': extractor.check_request_url,
                'URL_of_Anchor': extractor.check_anchor_urls,
                'Links_in_tags': extractor.count_links_in_tags,
                'SFH': extractor.check_sfh,
                'Submitting_to_email': extractor.check_email_submission,
                'Abnormal_URL': extractor.check_abnormal_url,
                'Redirect': extractor.count_redirects,
                'on_mouseover': extractor.check_mouseover,
                'RightClick': extractor.check_right_click,
                'popUpWidnow': extractor.check_popup_window,
                'Iframe': extractor.check_iframe,
                'age_of_domain': extractor.get_domain_age,
                'DNSRecord': extractor.check_dns_record,
                'web_traffic': extractor.estimate_traffic,
                'Page_Rank': extractor.estimate_page_rank,
                'Google_Index': extractor.check_google_index,
                'Links_pointing_to_page': extractor.count_external_links,
                'Statistical_report': extractor.check_stat_report
            }
            
            print("\n--- Feature Extraction Results ---")
            successful_features = {}
            failed_features = {}
            
            for feature_name, method in feature_methods.items():
                try:
                    value = method()
                    successful_features[feature_name] = value
                    print(f"✓ {feature_name}: {value}")
                except Exception as e:
                    failed_features[feature_name] = str(e)
                    print(f"✗ {feature_name}: ERROR - {str(e)}")
            
            print(f"\nSummary:")
            print(f"✓ Successful features: {len(successful_features)}")
            print(f"✗ Failed features: {len(failed_features)}")
            
            if failed_features:
                print(f"\nFailed features details:")
                for feature, error in failed_features.items():
                    print(f"  {feature}: {error}")
            
            return successful_features, failed_features
            
        except Exception as e:
            print(f"✗ Fatal error in feature extraction: {str(e)}")
            return {}, {'fatal_error': str(e)}

def main():
    """Main execution for debugging"""
    try:
        analyzer = FalsePositiveAnalyzer()
        
        # Test URLs - modify this list as needed
        test_urls = [
            "https://www.google.com",
            "https://www.microsoft.com",
            "https://www.flipkart.com",
            "http://east.dpsbangalore.edu.in/nios-admissions"
        ]
        
        print(f"\nAnalyzing {len(test_urls)} URLs...")
        
        # Debug first URL in detail
        if test_urls:
            print("\n" + "="*50)
            print("DETAILED DEBUG FOR FIRST URL")
            print("="*50)
            analyzer.debug_feature_extraction(test_urls[0])
        
        # Analyze all URLs
        print("\n" + "="*50)
        print("ANALYZING ALL URLs")
        print("="*50)
        results = analyzer.analyze_urls(test_urls)
        
        # Save and display results
        results.to_csv("false_positive_analysis.csv", index=False)
        print("\nAnalysis results saved to false_positive_analysis.csv")
        
        # Display summary
        if not results.empty:
            print("\nSummary of results:")
            print(results[['url', 'prediction', 'probability_phishing', 'error']])
            
            # Count successful analyses
            successful = results[results['error'].isna()]
            print(f"\nSuccessful analyses: {len(successful)}/{len(results)}")
            
            if len(successful) > 0:
                false_positives = successful[successful['prediction'] == 1]
                print(f"Found {len(false_positives)} potential false positives")
                if len(false_positives) > 0:
                    print("False positives:")
                    print(false_positives[['url', 'probability_phishing']])
                
                legitimate = successful[successful['prediction'] == 0]
                print(f"Found {len(legitimate)} legitimate sites")
                if len(legitimate) > 0:
                    print("Legitimate sites:")
                    print(legitimate[['url', 'probability_legitimate']])
            
            # Show errors if any
            errors = results[results['error'].notna()]
            if len(errors) > 0:
                print(f"\nErrors encountered for {len(errors)} URLs:")
                for _, row in errors.iterrows():
                    print(f"  {row['url']}: {row['error']}")
    
    except Exception as e:
        print(f"Fatal error in main: {str(e)}")
        import traceback
        print(f"Full traceback: {traceback.format_exc()}")

if __name__ == "__main__":
    main()