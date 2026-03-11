'use client';

import { useEffect, useState, Suspense } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import Link from 'next/link';

function VerifyEmailContent() {
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading');
  const [message, setMessage] = useState('');
  const searchParams = useSearchParams();
  const router = useRouter();

  useEffect(() => {
    const token = searchParams.get('token');
    
    if (!token) {
      setStatus('error');
      setMessage('Token de vérification manquant.');
      return;
    }

    const verifyEmail = async () => {
      try {
        const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'https://vulnscope-api.onrender.com/api/v1';
        const response = await fetch(`${apiUrl}/auth/verify-email`, {
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
        setStatus('error');
        setMessage('Erreur de connexion au serveur. Veuillez réessayer.');
      }
    };

    verifyEmail();
  }, [searchParams, router]);

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
                <Link
                  href="/?auth=register"
                  className="inline-flex items-center justify-center px-6 py-3 border border-transparent text-base font-medium rounded-lg text-white bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 transition-all"
                >
                  Réessayer l'inscription
                </Link>
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