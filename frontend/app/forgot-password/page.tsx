'use client';

import { useState, Suspense } from 'react';
import Link from 'next/link';
import { Mail, RefreshCw, ArrowLeft } from 'lucide-react';

function ForgotPasswordContent() {
  const [email, setEmail] = useState('');
  const [status, setStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle');
  const [message, setMessage] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!email) {
      setMessage('Veuillez entrer votre adresse email.');
      return;
    }

    setStatus('loading');
    setMessage('');

    try {
      const response = await fetch('/api/auth/forgot-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email }),
      });

      const data = await response.json();

      if (response.ok) {
        setStatus('success');
        setMessage('Si un compte existe avec cette adresse email, vous recevrez un lien de réinitialisation.');
      } else {
        // Show success message even if email doesn't exist (security)
        if (response.status === 404) {
          setStatus('success');
          setMessage('Si un compte existe avec cette adresse email, vous recevrez un lien de réinitialisation.');
        } else if (response.status === 429 || data.detail?.includes('Trop de requêtes')) {
          setStatus('error');
          setMessage('Trop de requêtes. Veuillez patienter quelques instants avant de réessayer.');
        } else {
          setStatus('error');
          setMessage(data.detail || 'Une erreur s\'est produite. Veuillez réessayer.');
        }
      }
    } catch (error) {
      console.error('Forgot password error:', error);
      setStatus('error');
      setMessage('Erreur de connexion au serveur. Veuillez réessayer.');
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-900 to-slate-800 p-4">
      <div className="w-full max-w-md">
        <div className="bg-card rounded-lg shadow-2xl p-8">
          {/* Header */}
          <Link
            href="/?auth=login"
            className="inline-flex items-center text-primary hover:underline text-sm mb-6"
          >
            <ArrowLeft className="h-4 w-4 mr-1" />
            Retour à la connexion
          </Link>

          <div className="flex items-center justify-center mb-8">
            <div className="bg-primary/10 p-4 rounded-lg">
              <Mail className="h-8 w-8 text-primary" />
            </div>
          </div>
          <h1 className="text-2xl font-bold text-center mb-2">Mot de passe oublié?</h1>
          <p className="text-center text-sm text-muted-foreground mb-6">
            Entrez votre adresse email et nous vous enverrons un lien pour réinitialiser votre mot de passe.
          </p>

          {status === 'success' ? (
            <div className="text-center">
              <div className="bg-green-500/10 text-green-500 p-4 rounded-lg mb-4">
                <p className="font-semibold">Email envoyé!</p>
                <p className="text-sm mt-2">{message}</p>
              </div>
              <p className="text-sm text-muted-foreground mb-4">
                Consultez votre boîte email pour le lien de réinitialisation.
              </p>
              <Link
                href="/?auth=login"
                className="inline-block bg-primary hover:bg-primary/90 text-primary-foreground font-semibold py-2 px-4 rounded-lg transition-colors"
              >
                Retour à la connexion
              </Link>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label htmlFor="email" className="block text-sm font-medium mb-2">
                  Adresse email
                </label>
                <input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="Entrez votre adresse email"
                  className="w-full px-4 py-2 border rounded-lg bg-slate-950 border-slate-700 focus:outline-none focus:ring-2 focus:ring-primary"
                  disabled={status === 'loading'}
                  required
                />
              </div>

              {message && status === 'error' && (
                <div className="p-3 rounded-lg bg-red-500/10 text-red-500 text-sm">
                  {message}
                </div>
              )}

              <button
                type="submit"
                disabled={status === 'loading'}
                className="w-full bg-primary hover:bg-primary/90 text-primary-foreground font-semibold py-2 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {status === 'loading' ? (
                  <>
                    <RefreshCw className="h-4 w-4 inline mr-2 animate-spin" />
                    Envoi en cours...
                  </>
                ) : (
                  'Envoyer le lien de réinitialisation'
                )}
              </button>

              <p className="text-center text-sm text-muted-foreground">
                Vous vous souvenez de votre mot de passe?{' '}
                <Link href="/?auth=login" className="text-primary hover:underline">
                  Se connecter
                </Link>
              </p>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}

export default function ForgotPasswordPage() {
  return (
    <Suspense fallback={<div>Chargement...</div>}>
      <ForgotPasswordContent />
    </Suspense>
  );
}
