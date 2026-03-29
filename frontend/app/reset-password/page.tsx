'use client';

import { useEffect, useState, Suspense } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { Key, RefreshCw, Eye, EyeOff } from 'lucide-react';

function ResetPasswordContent() {
  const [status, setStatus] = useState<'loading' | 'form' | 'success' | 'error'>('loading');
  const [message, setMessage] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [token, setToken] = useState<string | null>(null);
  const searchParams = useSearchParams();
  const router = useRouter();

  useEffect(() => {
    const resetToken = searchParams.get('token');
    
    if (!resetToken) {
      setStatus('error');
      setMessage('Token de réinitialisation manquant. Veuillez utiliser le lien reçu par email.');
      return;
    }

    setToken(resetToken);
    setStatus('form');
  }, [searchParams, router]);

  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!password || !confirmPassword) {
      setMessage('Veuillez remplir tous les champs.');
      return;
    }

    if (password !== confirmPassword) {
      setMessage('Les mots de passe ne correspondent pas.');
      return;
    }

    if (password.length < 8) {
      setMessage('Le mot de passe doit contenir au moins 8 caractères.');
      return;
    }

    setIsSubmitting(true);
    
    try {
      const response = await fetch('/api/auth/reset-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          token,
          new_password: password,
        }),
      });

      const data = await response.json();

      if (response.ok) {
        setStatus('success');
        setMessage('Votre mot de passe a été réinitialisé avec succès! Vous pouvez maintenant vous connecter.');
        // Redirect to login after 3 seconds
        setTimeout(() => {
          router.push('/?auth=login');
        }, 3000);
      } else {
        setStatus('error');
        if (response.status === 400 && data.detail?.includes('expiré')) {
          setMessage('Le lien de réinitialisation a expiré. Veuillez demander un nouveau lien.');
        } else if (response.status === 429 || data.detail?.includes('Trop de requêtes')) {
          setMessage('Trop de requêtes. Veuillez patienter quelques instants avant de réessayer.');
        } else {
          setMessage(data.detail || 'Erreur lors de la réinitialisation du mot de passe.');
        }
      }
    } catch (error) {
      console.error('Reset password error:', error);
      setStatus('error');
      setMessage('Erreur de connexion au serveur. Veuillez réessayer.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-900 to-slate-800 p-4">
      <div className="w-full max-w-md">
        <div className="bg-card rounded-lg shadow-2xl p-8">
          {/* Header */}
          <div className="flex items-center justify-center mb-8">
            <div className="bg-primary/10 p-4 rounded-lg">
              <Key className="h-8 w-8 text-primary" />
            </div>
          </div>
          <h1 className="text-2xl font-bold text-center mb-2">Réinitialiser le mot de passe</h1>
          <p className="text-center text-sm text-muted-foreground mb-6">
            Entrez votre nouveau mot de passe
          </p>

          {status === 'loading' && (
            <div className="text-center">
              <RefreshCw className="h-8 w-8 animate-spin mx-auto text-primary" />
              <p className="text-sm text-muted-foreground mt-4">Vérification du token...</p>
            </div>
          )}

          {status === 'form' && (
            <form onSubmit={handleResetPassword} className="space-y-4">
              {/* Password Field */}
              <div>
                <label htmlFor="password" className="block text-sm font-medium mb-2">
                  Nouveau mot de passe
                </label>
                <div className="relative">
                  <input
                    id="password"
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Entrez votre nouveau mot de passe"
                    className="w-full px-4 py-2 border rounded-lg bg-slate-950 border-slate-700 focus:outline-none focus:ring-2 focus:ring-primary"
                    disabled={isSubmitting}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  >
                    {showPassword ? (
                      <EyeOff className="h-5 w-5" />
                    ) : (
                      <Eye className="h-5 w-5" />
                    )}
                  </button>
                </div>
              </div>

              {/* Confirm Password Field */}
              <div>
                <label htmlFor="confirmPassword" className="block text-sm font-medium mb-2">
                  Confirmer le mot de passe
                </label>
                <div className="relative">
                  <input
                    id="confirmPassword"
                    type={showConfirmPassword ? 'text' : 'password'}
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="Confirmez votre mot de passe"
                    className="w-full px-4 py-2 border rounded-lg bg-slate-950 border-slate-700 focus:outline-none focus:ring-2 focus:ring-primary"
                    disabled={isSubmitting}
                  />
                  <button
                    type="button"
                    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  >
                    {showConfirmPassword ? (
                      <EyeOff className="h-5 w-5" />
                    ) : (
                      <Eye className="h-5 w-5" />
                    )}
                  </button>
                </div>
              </div>

              {message && (
                <div className="p-3 rounded-lg bg-red-500/10 text-red-500 text-sm">
                  {message}
                </div>
              )}

              <button
                type="submit"
                disabled={isSubmitting}
                className="w-full bg-primary hover:bg-primary/90 text-primary-foreground font-semibold py-2 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isSubmitting ? (
                  <>
                    <RefreshCw className="h-4 w-4 inline mr-2 animate-spin" />
                    Traitement...
                  </>
                ) : (
                  'Réinitialiser le mot de passe'
                )}
              </button>

              <p className="text-center text-sm text-muted-foreground">
                Retour à{' '}
                <Link href="/?auth=login" className="text-primary hover:underline">
                  la connexion
                </Link>
              </p>
            </form>
          )}

          {status === 'success' && (
            <div className="text-center">
              <div className="bg-green-500/10 text-green-500 p-4 rounded-lg mb-4">
                <p className="font-semibold">Succès!</p>
                <p className="text-sm mt-2">{message}</p>
              </div>
              <p className="text-sm text-muted-foreground">
                Redirection vers la connexion...
              </p>
            </div>
          )}

          {status === 'error' && (
            <div className="text-center">
              <div className="bg-red-500/10 text-red-500 p-4 rounded-lg mb-4">
                <p className="font-semibold">Erreur</p>
                <p className="text-sm mt-2">{message}</p>
              </div>
              <Link
                href="/?auth=login"
                className="inline-block bg-primary hover:bg-primary/90 text-primary-foreground font-semibold py-2 px-4 rounded-lg transition-colors mt-4"
              >
                Retour à la connexion
              </Link>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default function ResetPasswordPage() {
  return (
    <Suspense fallback={<div>Chargement...</div>}>
      <ResetPasswordContent />
    </Suspense>
  );
}
