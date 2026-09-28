alter table public.training_sessions
  add column if not exists description text;

comment on column public.training_sessions.description is
  'Descripción y detalles adicionales del evento o entrenamiento, incluyendo cantidad de personas, logística u otras indicaciones.';
