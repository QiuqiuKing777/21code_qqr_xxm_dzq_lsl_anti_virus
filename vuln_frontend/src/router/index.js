import { createRouter, createWebHistory } from 'vue-router';
import CnvdSelectPage from '../components/CnvdSelectPage.vue'; // 假设组件路径
import CveSelectPage from "@/components/CveSelectPage.vue";
import VulnSelectPage from "@/components/VulnSelectPage.vue";
import CompaniesSelectPage from "@/components/CompaniesSelectPage.vue";
import AffectSelectPage from "@/components/AffectSelectPage.vue";
import ProductSelectPage from "@/components/ProductSelectPage.vue";
import UsedSelectPage from "@/components/UsedSelectPage.vue";
import AtkMsgSelectPage from "@/components/AtkMsgSelectPage.vue";
import YaraUpload from "@/components/YaraUpload.vue";
import SigmaUpload from "@/components/SigmaUpload.vue";
import YaraScan from "@/components/YaraScan.vue";
import SigmaScan from "@/components/SigmaScan.vue";

import App from '../App.vue'

const routes = [
  {
    path: '/cnvd_database',
    name: 'CnvdSelectPage',
    component: CnvdSelectPage
  },
    {
    path: '/cve_database',
    name:'CveSelectPage',
    component: CveSelectPage
  },
    {
    path: '/vuln_database',
    name:'VulnSelectPage',
    component: VulnSelectPage
  },
    {
    path: '/company_database',
    name:'CompaniesSelectPage',
    component: CompaniesSelectPage
  },
    {
    path: '/affects_database',
    name:'AffectSelectPage',
    component: AffectSelectPage
  },
    {
    path: '/product_database',
    name:'ProductSelectPage',
    component: ProductSelectPage
  },
    {
    path: '/used_database',
    name:'UsedSelectPage',
    component: UsedSelectPage
  },
    {
    path: '/atkmsg_database',
    name:'AtkMsgSelectPage',
    component: AtkMsgSelectPage
  },
    {
    path:'/yara_upload',
    name:'YaraUpload',
    component: YaraUpload
  },
    {
    path:'/sigma_upload',
    name:'SigmaUpload',
    component: SigmaUpload
  },
  {
    path:'/yara_scan',
    name:'YaraScan',
    component: YaraScan
  },
  {
    path:'/sigma_scan',
    name:'SigmaScan',
    component: SigmaScan
  }
];



const router = createRouter({
  history: createWebHistory(),
  routes
});

export default router;