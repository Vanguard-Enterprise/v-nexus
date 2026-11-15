import { Route, Routes } from "react-router";
import { ClusterPage } from "./pages/ClusterPage";
import { NotFoundPage } from "./pages/NotFoundPage";
import { ProjectPage } from "./pages/ProjectPage";
import { ProjectsPage } from "./pages/ProjectsPage";
import { ResourcePage } from "./pages/ResourcePage";

/** Client-side routes. vn-server answers unknown non-API paths with index.html, so deep links load. */
export function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<ProjectsPage />} />
      <Route path="/projects/:slug" element={<ProjectPage />} />
      <Route path="/projects/:slug/clusters/:clusterId" element={<ClusterPage />} />
      <Route path="/projects/:slug/clusters/:clusterId/resources/:resourceId" element={<ResourcePage />} />
      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  );
}
