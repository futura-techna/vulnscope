import { metadata } from './layout'

describe('RootLayout', () => {
  describe('metadata', () => {
    it('should have correct title', () => {
      expect(metadata.title).toBe('VulnScope Dashboard')
    })

    it('should have correct description', () => {
      expect(metadata.description).toBe('Dynamic Application Security Testing Platform')
    })

    it('should have favicon configured', () => {
      expect(metadata.icons).toEqual({
        icon: '/favicon.ico',
      })
    })
  })
})