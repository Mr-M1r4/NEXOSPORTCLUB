-- Record the production hotfix in version control.
-- The helper only generates a random reference string and does not read or mutate
-- financial records. Keep anonymous access revoked; authenticated access is needed
-- by the existing payment-registration flow, which calls this helper directly.
grant execute on function private.generate_payment_reference(text) to authenticated;

comment on function private.generate_payment_reference(text) is
  'Generates opaque payment references only; executable by authenticated clients that need a reference before payment insert. Does not read or modify payment records.';
