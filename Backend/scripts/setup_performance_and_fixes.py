"""Creates performance functions, triggers, and schema updates in Supabase.

Run from the Backend folder: python -m scripts.setup_performance_and_fixes
"""
from __future__ import annotations

import config
from web import db

STATEMENTS = [
    "ALTER TABLE public.global_urls ADD COLUMN IF NOT EXISTS notes text",
    """
    CREATE OR REPLACE FUNCTION public.set_updated_at()
    RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = public
    AS $$
    BEGIN
      NEW.updated_at := now();
      RETURN NEW;
    END;
    $$
    """,
    "DROP TRIGGER IF EXISTS trg_global_urls_updated_at ON public.global_urls",
    """
    CREATE TRIGGER trg_global_urls_updated_at
      BEFORE UPDATE ON public.global_urls
      FOR EACH ROW
      EXECUTE FUNCTION public.set_updated_at()
    """,
    "DROP TRIGGER IF EXISTS trg_detection_lists_updated_at ON public.detection_lists",
    """
    CREATE TRIGGER trg_detection_lists_updated_at
      BEFORE UPDATE ON public.detection_lists
      FOR EACH ROW
      EXECUTE FUNCTION public.set_updated_at()
    """,
    "DROP TRIGGER IF EXISTS trg_users_updated_at ON public.users",
    """
    CREATE TRIGGER trg_users_updated_at
      BEFORE UPDATE ON public.users
      FOR EACH ROW
      EXECUTE FUNCTION public.set_updated_at()
    """,
    """
    CREATE OR REPLACE FUNCTION public.get_lists_summary()
    RETURNS jsonb
    LANGUAGE plpgsql
    STABLE
    SET search_path = public
    AS $$
    DECLARE
      v_top_n int;
      v_manual int;
      v_not_trusted int;
      v_tranco int;
      v_manual_bl int;
      v_admin_bl int;
      v_shared int;
      v_adult_manual int;
      v_top_sync timestamptz;
      v_feed_count int := 0;
      v_feed_sync timestamptz;
      v_adult_count int := 0;
      v_adult_sync timestamptz;
    BEGIN
      SELECT coalesce((SELECT NULLIF(value, '')::int FROM public.detection_settings WHERE key = 'whitelist_top_n'), 10000)
        INTO v_top_n;

      SELECT
        count(*) FILTER (WHERE list_type = 'whitelist' AND is_active),
        count(*) FILTER (WHERE list_type = 'not_trusted' AND is_active),
        count(*) FILTER (WHERE list_type = 'blacklist' AND is_active),
        count(*) FILTER (WHERE list_type = 'shared_hosts' AND is_active),
        count(*) FILTER (WHERE list_type = 'adult_manual' AND is_active)
      INTO v_manual, v_not_trusted, v_manual_bl, v_shared, v_adult_manual
      FROM public.detection_lists;

      SELECT count(*) INTO v_tranco
      FROM public.trusted_top_sites t
      WHERE t.rank <= v_top_n
        AND NOT EXISTS (
          SELECT 1 FROM public.detection_lists d
          WHERE d.list_type = 'not_trusted' AND d.is_active AND d.value = t.domain
        );

      SELECT count(*) INTO v_admin_bl
      FROM public.global_urls
      WHERE status = 'active' AND risk_level IN ('suspicious', 'malicious');

      SELECT synced_at INTO v_top_sync FROM public.list_sync_status WHERE name = 'trusted_top_sites';
      SELECT coalesce(row_count, 0), synced_at INTO v_feed_count, v_feed_sync FROM public.list_sync_status WHERE name = 'threat_feed_urls';
      SELECT coalesce(row_count, 0), synced_at INTO v_adult_count, v_adult_sync FROM public.list_sync_status WHERE name = 'adult_domains';

      RETURN jsonb_build_object(
        'trusted', jsonb_build_object(
          'count', v_tranco + v_manual,
          'top_sites', v_tranco,
          'manual', v_manual,
          'not_trusted', v_not_trusted,
          'top_n', v_top_n,
          'synced_at', v_top_sync
        ),
        'blocked', jsonb_build_object(
          'count', v_manual_bl + v_admin_bl,
          'manual', v_manual_bl,
          'admin_approved', v_admin_bl
        ),
        'feed', jsonb_build_object(
          'count', coalesce(v_feed_count, 0),
          'synced_at', v_feed_sync
        ),
        'adult', jsonb_build_object(
          'count', coalesce(v_adult_count, 0) + v_adult_manual,
          'synced_at', v_adult_sync
        ),
        'shared', jsonb_build_object(
          'count', v_shared
        )
      );
    END;
    $$
    """,
    """
    CREATE OR REPLACE FUNCTION public.review_whitelist_request(
      p_req_id uuid,
      p_reviewer_id uuid,
      p_decision text,
      p_note text
    )
    RETURNS text
    LANGUAGE plpgsql
    SET search_path = public
    AS $$
    DECLARE
      v_row record;
      v_new text;
    BEGIN
      SELECT user_id, domain, path_prefix, status
      INTO v_row
      FROM public.whitelist_requests
      WHERE id = p_req_id
      FOR UPDATE;

      IF NOT FOUND THEN
        RETURN 'not_found';
      END IF;

      IF v_row.status <> 'pending' THEN
        RETURN 'conflict';
      END IF;

      v_new := CASE WHEN p_decision = 'approve' THEN 'approved' ELSE 'rejected' END;

      IF v_new = 'approved' THEN
        INSERT INTO public.whitelist_entries (scope, user_id, domain, path_prefix, added_by, request_id)
        VALUES ('global', NULL, v_row.domain, v_row.path_prefix, p_reviewer_id, p_req_id)
        ON CONFLICT DO NOTHING;
      END IF;

      UPDATE public.whitelist_requests
      SET status = v_new,
          review_note = NULLIF(p_note, ''),
          reviewed_by = p_reviewer_id,
          reviewed_at = now()
      WHERE id = p_req_id;

      RETURN 'ok';
    END;
    $$
    """,
]


def main() -> None:
    db.init_pool(config.DATABASE_URL)
    with db.transaction() as c:
        for stmt in STATEMENTS:
            c.execute(stmt)
    print("Applied performance functions and triggers successfully.")


if __name__ == "__main__":
    main()
