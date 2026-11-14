import { describe, it, expect, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import EntityPopover from './EntityPopover'
import type { Entity } from '../types'

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

describe('EntityPopover — Escape already taken by a menu or dialog above', () => {
  it('does not close on an Escape whose default was already prevented', () => {
    const { onClose } = renderPopover('APT29')
    const event = new KeyboardEvent('keydown', { key: 'Escape', cancelable: true })
    event.preventDefault()
    window.dispatchEvent(event)
    expect(onClose).not.toHaveBeenCalled()
  })

  it('closes once on an Escape nothing else took', () => {
    const { onClose } = renderPopover('APT29')
    fireEvent.keyDown(document.body, { key: 'Escape' })
    expect(onClose).toHaveBeenCalledTimes(1)
  })
})

describe('EntityPopover — Escape after « ← Back » on the format warning (#824)', () => {
  // An edit of a domain to an IPv4: the warning shows, « ← Back » hides it and brings the search input back.
  function renderEdit(onClose = vi.fn()) {
    const entity = { id: 'e1', entity_type: 'domain', value: 'evil.com' } as Entity
    render(
      <EntityPopover
        state={{ mode: 'edit', x: 100, y: 100, entity }}
        onClose={onClose}
        onChangeType={vi.fn()}
      />,
    )
    return onClose
  }

  it('closes once on Escape after going back, with the focus on nothing', async () => {
    const user = userEvent.setup()
    const onClose = renderEdit()

    await user.click(screen.getByRole('button', { name: /^IPv4/ }))
    expect(await screen.findByText('Format does not match')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '← Back' }))

    fireEvent.keyDown(document.body, { key: 'Escape' })
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('closes once on Escape in the search input', async () => {
    const onClose = renderEdit()
    fireEvent.keyDown(screen.getByPlaceholderText('Filter types…'), { key: 'Escape' })
    expect(onClose).toHaveBeenCalledTimes(1)
  })
})
