'use client';

import { useEffect, useState, Suspense } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { Mail, RefreshCw } from 'lucide-react';

function VerifyEmailContent() {
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading');
  const [message, setMessage] = useState('');
  const [resendEmail, setResendEmail] = useState('');
  const [resendStatus, setResendStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle');
  const [resendMessage, setResendMessage] = useState('');
  const [retryCount, setRetryCount] = useState(0);
  const [isRetrying, setIsRetrying] = useState(false);
  const searchParams = useSearchParams();
  const router = useRouter();

  const verifyEmail = async (token: string, isRetry: boolean = false) => {
    if (isRetry) {
      setIsRetrying(true);
    }
    
    try {
      // Use relative URL to go through Next.js API route
      const response = await fetch('/api/auth/verify-email', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ token }),
      });

      const data = await response.json();

      if (response.ok) {
        setStatus('success');
        setMessage('Votre email a été vérifié avec succès! Vous pouvez maintenant vous connecter.');
        // Redirect to login after 3 seconds
        setTimeout(() => {
          router.push('/?auth=login');
        }, 3000);
      } else {
        setStatus('error');
        setMessage(data.detail || 'Erreur lors de la vérification de l\'email.');
      }
    } catch (error) {
      console.error('Verification error:', error);
      setStatus('error');
      setMessage('Erreur de connexion au serveur. Veuillez réessayer.');
    } finally {
      setIsRetrying(false);
    }
  };

  useEffect(() => {
    const token = searchParams.get('token');
    
    if (!token) {
      setStatus('error');
      setMessage('Token de vérification manquant. Veuillez utiliser le lien reçu par email.');
      return;
    }

    verifyEmail(token);
  }, [searchParams, router]);

  const handleRetry = () => {
    const token = searchParams.get('token');
    if (token) {
      setRetryCount(prev => prev + 1);
      setStatus('loading');
      verifyEmail(token, true);
    }
  };

  const handleResendVerification = async (e: React.FormEvent) => {
    e.preventDefault();
    setResendStatus('loading');
    setResendMessage('');

    try {
      const response = await fetch('/api/auth/resend-verification', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email: resendEmail }),
      });

      const data = await response.json();
      
      setResendStatus('success');
      setResendMessage(data.message || 'Un nouvel email de vérification a été envoyé.');
      
      // If verification URL is returned (email disabled mode), show it
      if (data.verification_url || data.debug_url) {
        const verifyUrl = data.verification_url || data.debug_url;
        console.log('[Resend] Verification URL:', verifyUrl);
        setResendMessage(data.message);
        
        // Store the URL and show a link instead of auto-redirect
        // Auto-redirect after 3 seconds
        setTimeout(() => {
          window.location.href = verifyUrl;
        }, 3000);
      }
    } catch (error) {
      console.error('Resend verification error:', error);
      setResendStatus('error');
      setResendMessage('Erreur lors de l\'envoi. Veuillez réessayer.');
    }
  };

  return (
    <div className="min-h-screen bg-gray-900 flex items-center justify-center px-4">
      <div className="max-w-md w-full">
        <div className="bg-gray-800 rounded-2xl shadow-xl p-8 border border-gray-700">
          {/* Logo */}
          <div className="text-center mb-8">
            <Link href="/" className="inline-flex items-center space-x-2">
              <span className="text-3xl">🛡️</span>
              <span className="text-2xl font-bold bg-gradient-to-r from-purple-400 to-pink-400 bg-clip-text text-transparent">
                VulnScope
              </span>
            </Link>
          </div>

          {/* Status Content */}
          <div className="text-center">
            {status === 'loading' && (
              <>
                <div className="animate-spin rounded-full h-16 w-16 border-4 border-purple-500 border-t-transparent mx-auto mb-6"></div>
                <h1 className="text-xl font-semibold text-white mb-2">
                  Vérification en cours...
                </h1>
                <p className="text-gray-400">
                  Veuillez patienter pendant que nous vérifions votre email.
                </p>
              </>
            )}

            {status === 'success' && (
              <>
                <div className="w-16 h-16 bg-green-500/20 rounded-full flex items-center justify-center mx-auto mb-6">
                  <svg className="w-8 h-8 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                </div>
                <h1 className="text-xl font-semibold text-white mb-2">
                  Email vérifié!
                </h1>
                <p className="text-gray-400 mb-6">
                  {message}
                </p>
                <p className="text-sm text-gray-500">
                  Redirection vers la page de connexion...
                </p>
              </>
            )}

            {status === 'error' && (
              <>
                <div className="w-16 h-16 bg-red-500/20 rounded-full flex items-center justify-center mx-auto mb-6">
                  <svg className="w-8 h-8 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </div>
                <h1 className="text-xl font-semibold text-white mb-2">
                  Erreur de vérification
                </h1>
                <p className="text-gray-400 mb-6">
                  {message}
                </p>
                
                {/* Retry button for service unavailable errors */}
                {(message.includes('indisponible') || message.includes('expiré') || message.includes('connecter')) && (
                  <button
                    onClick={handleRetry}
                    disabled={isRetrying}
                    className="w-full mb-4 px-4 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                  >
                    {isRetrying ? (
                      <>
                        <RefreshCw className="h-4 w-4 animate-spin" />
                        Nouvelle tentative...
                      </>
                    ) : (
                      <>
                        <RefreshCw className="h-4 w-4" />
                        Réessayer la vérification
                      </>
                    )}
                  </button>
                )}
                
                {/* Resend verification form */}
                <div className="bg-gray-700/50 rounded-lg p-4 mb-4">
                  <p className="text-sm text-gray-300 mb-3">
                    <Mail className="inline h-4 w-4 mr-1" />
                    Demander un nouvel email de vérification:
                  </p>
                  <form onSubmit={handleResendVerification} className="space-y-3">
                    <input
                      type="email"
                      value={resendEmail}
                      onChange={(e) => setResendEmail(e.target.value)}
                      placeholder="Votre adresse email"
                      className="w-full px-4 py-2 bg-gray-600 border border-gray-500 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500"
                      required
                    />
                    <button
                      type="submit"
                      disabled={resendStatus === 'loading'}
                      className="w-full px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                    >
                      {resendStatus === 'loading' ? (
                        <>
                          <RefreshCw className="h-4 w-4 animate-spin" />
                          Envoi en cours...
                        </>
                      ) : (
                        <>
                          <Mail className="h-4 w-4" />
                          Renvoyer l'email
                        </>
                      )}
                    </button>
                  </form>
                  
                  {resendStatus === 'success' && (
                    <p className="mt-3 text-sm text-green-400">{resendMessage}</p>
                  )}
                  {resendStatus === 'error' && (
                    <p className="mt-3 text-sm text-red-400">{resendMessage}</p>
                  )}
                </div>
                
                <div className="mt-4">
                  <Link
                    href="/?auth=register"
                    className="inline-flex items-center justify-center px-6 py-3 border border-gray-600 text-base font-medium rounded-lg text-gray-300 hover:bg-gray-700 transition-all"
                  >
                    Retour à l'inscription
                  </Link>
                </div>
              </>
            )}
          </div>

          {/* Footer */}
          <div className="mt-8 pt-6 border-t border-gray-700 text-center">
            <p className="text-sm text-gray-500">
              Besoin d'aide?{' '}
              <a href="mailto:support@vulnscope.com" className="text-purple-400 hover:text-purple-300">
                Contactez le support
              </a>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function VerifyEmailPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="animate-spin rounded-full h-16 w-16 border-4 border-purple-500 border-t-transparent"></div>
      </div>
    }>
      <VerifyEmailContent />
    </Suspense>
  );
}