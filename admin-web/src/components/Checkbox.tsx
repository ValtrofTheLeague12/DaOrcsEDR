import Icon from './Icon'

// ---------------------------------------------------------------------------
// The checkbox, drawn rather than surrendered to the OS.
//
// A native checkbox can only be tinted (accent-color); its shape, border and
// checkmark are whatever the desktop theme says, so the same "yes" looks
// different on the test picker, the sample factory and the YARA options -
// sometimes a blue square, sometimes a flat white one. This draws the box:
// a rounded square that fills with the accent colour and turns the shared
// check icon white while checked, with the real input underneath keeping every
// native behaviour (click, focus, keyboard, label association, forms).
//
// The visual part is aria-hidden, because the input already IS the checkbox
// as far as a screen reader is concerned; the drawn box is decoration over it,
// not a second control for anyone to be quoted twice.
// ---------------------------------------------------------------------------

export default function Checkbox({ checked, disabled, onChange }: {
  checked: boolean
  disabled?: boolean
  onChange: (next: boolean) => void
}) {
  return (
    <span className={'checkbox' + (checked ? ' is-checked' : '') + (disabled ? ' is-disabled' : '')}>
      <input
        type="checkbox"
        className="checkbox-input"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.currentTarget.checked)}
      />
      <span className="checkbox-box" aria-hidden="true">
        <Icon name="check" size={10} />
      </span>
    </span>
  )
}
