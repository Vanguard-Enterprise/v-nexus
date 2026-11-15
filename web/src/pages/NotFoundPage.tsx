import { Link } from "react-router";
import { useDocumentTitle } from "../lib/title";

export function NotFoundPage() {
  useDocumentTitle("Page not found");
  return (
    <div className="page-head">
      <h1>Page not found</h1>
      <p className="page-head__lede">
        There is no page at this address. <Link to="/">Go to your projects</Link>.
      </p>
    </div>
  );
}
