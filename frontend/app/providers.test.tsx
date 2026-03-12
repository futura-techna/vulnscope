import { render, screen } from '@testing-library/react'
import { Providers } from './providers'

// Mock next-auth
jest.mock('next-auth/react', () => ({
  SessionProvider: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="session-provider">{children}</div>
  )
}))

// Mock react-query
jest.mock('@tanstack/react-query', () => ({
  QueryClientProvider: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="query-client-provider">{children}</div>
  ),
  QueryClient: jest.fn().mockImplementation(() => ({
    defaultOptions: {},
  })),
}))

describe('Providers', () => {
  it('should render children wrapped in providers', () => {
    render(
      <Providers>
        <div data-testid="child">Test Child</div>
      </Providers>
    )

    expect(screen.getByTestId('child')).toBeInTheDocument()
    expect(screen.getByTestId('session-provider')).toBeInTheDocument()
    expect(screen.getByTestId('query-client-provider')).toBeInTheDocument()
  })

  it('should wrap children in SessionProvider', () => {
    render(
      <Providers>
        <div>Test Content</div>
      </Providers>
    )

    expect(screen.getByTestId('session-provider')).toBeInTheDocument()
  })

  it('should wrap children in QueryClientProvider', () => {
    render(
      <Providers>
        <div>Test Content</div>
      </Providers>
    )

    expect(screen.getByTestId('query-client-provider')).toBeInTheDocument()
  })
})