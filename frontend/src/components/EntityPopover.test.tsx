import { describe, it, expect, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import EntityPopover from './EntityPopover'

// The create popover picks a type for the selected text.  An IoC whose format
// does not match asks first ("Format does not match"); a defanged IoC is refanged
// before it is checked, so the analyst's copy of a report needs no edit (#554).

function renderPopover(text: string, onClose = vi.fn(), onCreate = vi.fn()) {
  render(
    <EntityPopover
      state={{ mode: 'create', x: 100, y: 100, text }}
      onClose={onClose}
      onCreate={onCreate}
    />,
  )
  return { onClose, onCreate }
}

describe('EntityPopover — defanged IoCs (#554)', () => {
  it.each([
    ['evil[.]com', 'Domain'],
    ['192.168.1[.]1', 'IPv4'],
    ['hxxps://evil.example/gate.php', 'URL'],
    ['user[@]host.com', 'Email'],
    ['hxxp[://]evil[.]com', 'URL'],
  ])('accepts %s as %s without the format warning', async (text, label) => {
    const user = userEvent.setup()
    const { onCreate } = renderPopover(text)

    await user.click(screen.getByRole('button', { name: new RegExp(`^${label}`) }))

    expect(screen.queryByText('Format does not match')).not.toBeInTheDocument()
    expect(onCreate).toHaveBeenCalledWith(text, expect.any(String))
  })

  it('still warns about a defanged IoC whose refanged form does not match', async () => {
    const user = userEvent.setup()
    const { onCreate } = renderPopover('evil[.]com')

    await user.click(screen.getByRole('button', { name: /^IPv4/ }))

    expect(await screen.findByText('Format does not match')).toBeInTheDocument()
    expect(onCreate).not.toHaveBeenCalled()
  })
})

describe('EntityPopover — Escape while the format warning is shown (#559)', () => {
  it('closes the popover when Escape is pressed on the warning', async () => {
    const user = userEvent.setup()
    const { onClose, onCreate } = renderPopover('evil.com')

    await user.click(screen.getByRole('button', { name: /^IPv4/ }))
    expect(await screen.findByText('Format does not match')).toBeInTheDocument()

    fireEvent.keyDown(document.body, { key: 'Escape' })

    expect(onClose).toHaveBeenCalledTimes(1)
    expect(onCreate).not.toHaveBeenCalled()
  })
})
